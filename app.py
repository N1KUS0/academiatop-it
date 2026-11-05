"""Академия ТОП — IT-портал: компьютеры, ПО, заявки."""
import csv
import gzip
import hashlib
import io
import json
import os
import secrets
import sqlite3
import tempfile
import threading
import time
from datetime import date, datetime, timedelta, timezone
from functools import wraps

import click
from flask import (Flask, Response, abort, flash, g, has_request_context, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from flask.sessions import SecureCookieSessionInterface
from werkzeug.security import check_password_hash, generate_password_hash

import db
import inventory
import netmap
import shutdown
import telegram
from db import (CATEGORIES, COMPUTERS_SQL, LICENSE_TYPES, STATUSES, TICKET_KINDS,
                TICKET_OPEN, TICKET_STATUSES, aud_code, computer_dict, get_db,
                parse_aud_code, parse_hostname, pc_hostname)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Название сайта в шапке, заголовке вкладки и подвале.
SITE_NAME = "Академия ТОП"
SITE_TAGLINE = "IT-портал"
SITE_AUTHOR = "n1kuso"

app = Flask(__name__)
app.config.update(
    DATABASE=os.environ.get("REGISTRY_DB", os.path.join(BASE_DIR, "instance", "registry.db")),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),  # самый долгий вход — с «Запомнить меня»
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,
)
os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
# Последний принятый архив автовыгрузки — чтобы применить новые сопоставления без ожидания следующей выгрузки.
LAST_ARCHIVE = os.path.join(os.path.dirname(app.config["DATABASE"]), "inventory_last.zip")


def _load_secret_key():
    key = os.environ.get("REGISTRY_SECRET_KEY")
    if key:
        return key
    path = os.path.join(os.path.dirname(app.config["DATABASE"]), "secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app.secret_key = _load_secret_key()

# Вход живёт 12 часов с последнего захода, а с «Запомнить меня» — 30 дней.
SESSION_LIFETIME = timedelta(hours=12)
REMEMBER_LIFETIME = timedelta(days=30)


class RememberSessionInterface(SecureCookieSessionInterface):
    """Срок cookie входа зависит от галочки «Запомнить меня»."""

    def get_expiration_time(self, app, session):
        if not session.permanent:
            return None
        return datetime.now(timezone.utc) + (REMEMBER_LIFETIME if session.get("remember") else SESSION_LIFETIME)


app.session_interface = RememberSessionInterface()
app.teardown_appcontext(db.close_db)

with app.app_context():
    db.init_db()


# --------------------------------------------------------------------------- auth / csrf

# Блокировка перебора: столько неудачных входов с одного IP за окно — и вход с него закрыт.
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW = 15 * 60


def client_ip():
    # X-Real-IP всегда перезаписывает nginx сервера академии (для зеркала — реальным IP посетителя).
    return request.headers.get("X-Real-IP") or request.remote_addr or "?"


# Минимальная длина пароля: вход доступен из интернета.
MIN_PASSWORD_LEN = 6
# Администратор может менять и удалять данные, поэтому его пароль длиннее.
ADMIN_MIN_PASSWORD_LEN = 12
# Страницы, доступные без входа. API импорта авторизуется своим токеном.
PUBLIC_ENDPOINTS = {"login", "logout", "forgot_password", "static", "api_inventory", "robots"}


def password_marker(pw_hash=None):
    """Часть хеша пароля: после смены пароля старые сессии перестают действовать."""
    return (get_setting_safe("admin_password") if pw_hash is None else pw_hash)[-16:]


# Пользователь вместе с версией аватарки (NULL — аватарки нет).
USERS_SQL = "SELECT u.*, av.version AS avatar FROM users u LEFT JOIN user_avatars av ON av.user_id = u.id"


def current_user():
    """Вошедший пользователь: dict(id, username, name, admin) или None."""
    if "_user" not in g:
        g._user = None
        now = int(time.time())
        if not session.get("remember") and now - session.get("seen", now) > SESSION_LIFETIME.total_seconds():
            session.clear()  # без «Запомнить меня» вход истекает через 12 часов без заходов
        if session.get("admin") is True and session.get("pwm") == password_marker():
            g._user = dict(id=None, username=get_setting_safe("admin_user"),
                           name="Администратор", admin=True, avatar=None)
        elif session.get("uid"):
            row = get_db().execute(USERS_SQL + " WHERE u.id = ?", (session["uid"],)).fetchone()
            # Удалённый пользователь или сменённый пароль — сессия больше не действует.
            if row and session.get("pwm") == password_marker(row["password_hash"]):
                g._user = dict(id=row["id"], username=row["username"],
                               name=row["full_name"] or row["username"], admin=False, avatar=row["avatar"],
                               must_change=bool(row["must_change_password"]))
        if g._user and now - session.get("seen", 0) > 60:
            session["seen"] = now
    return g._user


def is_admin():
    user = current_user()
    return bool(user and user["admin"])


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_admin():
            flash("Это действие доступно только администратору.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def require_login():
    if request.endpoint in PUBLIC_ENDPOINTS or current_user():
        return None
    nxt = request.full_path.rstrip("?") if request.method == "GET" else ""
    return redirect(url_for("login", next=nxt) if nxt and nxt != "/" else url_for("login"))


@app.before_request
def require_password_change():
    """Пароль выдал администратор (новый пользователь или сброс) — пока не задан свой, сайт недоступен."""
    user = current_user()
    if user and user.get("must_change") and request.endpoint not in ("account", "logout", "static", "robots"):
        return redirect(url_for("account"))


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def check_csrf():
    # API импорта авторизуется своим токеном, CSRF к нему не относится.
    if request.method == "POST" and not request.path.startswith("/api/"):
        sent = request.form.get("csrf_token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Неверный CSRF-токен. Обновите страницу и повторите.")


_static_versions = {}


def static_url(filename):
    """Ссылка на файл из static/ с версией по содержимому. nginx отдаёт статику с expires 7d,
    и без версии браузер (особенно на телефоне) после обновления сайта показывал бы старые стили и скрипты."""
    if filename not in _static_versions:
        with open(os.path.join(app.static_folder, filename), "rb") as f:
            _static_versions[filename] = hashlib.md5(f.read()).hexdigest()[:10]
    return url_for("static", filename=filename, v=_static_versions[filename])


# Глобальные переменные нужны и в импортируемых макросах, поэтому не через context_processor.
app.jinja_env.globals.update(csrf_token=csrf_token, static_url=static_url, SITE_NAME=SITE_NAME, SITE_TAGLINE=SITE_TAGLINE,
                             SITE_AUTHOR=SITE_AUTHOR, CATEGORIES=CATEGORIES,
                             LICENSE_TYPES=LICENSE_TYPES, STATUSES=STATUSES,
                             TICKET_KINDS=TICKET_KINDS, TICKET_STATUSES=TICKET_STATUSES)


def tickets_unread():
    """Сколько заявок с новыми сообщениями для текущего пользователя (для значка в меню)."""
    user = current_user()
    if not user:
        return 0
    if user["admin"]:
        sql, params = "SELECT COUNT(*) FROM tickets WHERE admin_unread = 1", ()
    else:
        sql, params = "SELECT COUNT(*) FROM ticket_watchers WHERE unread = 1 AND user_id = ?", (user["id"],)
    return get_db().execute(sql, params).fetchone()[0]


@app.context_processor
def inject_globals():
    return dict(is_admin=is_admin(), current_user=current_user(), today=date.today().isoformat(),
                tickets_unread=tickets_unread())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        conn = get_db()
        ip = client_ip()
        now = time.time()
        conn.execute("DELETE FROM login_failures WHERE ts < ?", (now - LOGIN_WINDOW,))
        failures = conn.execute("SELECT COUNT(*) FROM login_failures WHERE ip = ?", (ip,)).fetchone()[0]
        if failures >= LOGIN_MAX_FAILURES:
            conn.commit()
            app.logger.warning("login blocked: ip=%s", ip)
            flash(f"Слишком много неудачных попыток. Вход с вашего адреса закрыт на {LOGIN_WINDOW // 60} минут.",
                  "danger")
            return render_template("login.html"), 429
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admin_user = get_setting_safe("admin_user")
        admin_hash = get_setting_safe("admin_password")
        row = None
        if admin_hash and username == admin_user:
            ok = check_password_hash(admin_hash, password)
        else:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            ok = bool(row) and check_password_hash(row["password_hash"], password)
        if ok:
            conn.execute("DELETE FROM login_failures WHERE ip = ?", (ip,))
            session.clear()
            session["remember"] = request.form.get("remember") == "1"
            session["seen"] = int(time.time())
            if row is None:
                session["admin"] = True
                session["pwm"] = password_marker()
            else:
                session["uid"] = row["id"]
                session["pwm"] = password_marker(row["password_hash"])
                conn.execute("UPDATE users SET last_login = ? WHERE id = ?",
                             (time.strftime("%Y-%m-%d %H:%M"), row["id"]))
            conn.commit()
            app.logger.warning("login ok: user=%s ip=%s", username, ip)
            session.permanent = True
            flash("Вы вошли как администратор." if row is None else "Вы вошли.", "success")
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("index"))
        conn.execute("INSERT INTO login_failures (ip, ts) VALUES (?, ?)", (ip, now))
        conn.commit()
        app.logger.warning("login failed: user=%s ip=%s", username[:50], ip)
        time.sleep(1)  # притормаживаем перебор паролей
        if not admin_hash and username == admin_user:
            flash("Пароль администратора ещё не задан. Выполните на сервере: flask --app app set-password", "danger")
        else:
            left = LOGIN_MAX_FAILURES - failures - 1
            flash("Неверный логин или пароль." + (f" Осталось попыток: {left}." if left < 3 else ""), "danger")
    elif current_user():
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Вы вышли.", "info")
    return redirect(url_for("login"))


def get_setting_safe(key):
    return db.get_setting(key, "")


@app.cli.command("netmap-check")
def netmap_check_command():
    """Проверить, может ли сервер пинговать ПК для блока «ПК в сети» на главной."""
    computers = [c for c in list_computers() if c["status"] != "decommissioned"]
    steps = []
    try:  # отдельный прогон ping — чтобы показать, каким способом сервер пингует
        netmap.ping_many(["127.0.0.1"], explain=steps)
    except netmap.PingUnavailable as e:
        steps.append(str(e))
    for s in steps:
        click.echo(f"  {s}")
    up, _at, error, details = netmap.status(computers)
    if error:
        click.echo(error)
        return
    click.echo(f"В сети: {len(up)} из {len(computers)} (адрес известен у {len(details)})")
    for c in computers:
        host = c["hostname"]
        state = "В СЕТИ" if host in up else "не в сети"
        found = details.get(host)
        click.echo(f"  {host:10} {state:9}  " + ("; ".join(f"{ip} ({src}): {verdict}" for ip, src, verdict in found)
                                                if found else "адрес неизвестен: нет в DNS и нет «IP: …» в примечании"))


@app.cli.command("set-password")
@click.option("--username", default="admin", show_default=True)
@click.password_option(prompt="Новый пароль администратора")
def set_password(username, password):
    """Задать логин и пароль администратора."""
    if validate_password(password, admin=True):
        raise click.ClickException(validate_password(password, admin=True))
    if get_db().execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        raise click.ClickException(f"Логин «{username}» уже занят пользователем с правом просмотра.")
    db.set_setting("admin_user", username)
    db.set_setting("admin_password", generate_password_hash(password))
    click.echo(f"Готово. Логин: {username}")


# --------------------------------------------------------------------------- пользователи (просмотр)

def validate_username(username, user_id=None):
    """Текст ошибки или None. user_id — пользователь, которого переименовывают (его старый логин не занят)."""
    if not username or len(username) > 50 or any(ch.isspace() for ch in username):
        return "Логин не может быть пустым, длиннее 50 символов или содержать пробелы."
    if username.lower() == get_setting_safe("admin_user").lower():
        return "Этот логин занят администратором."
    if get_db().execute("SELECT 1 FROM users WHERE username = ? AND id IS NOT ?", (username, user_id)).fetchone():
        return f"Пользователь «{username}» уже есть."
    return None


def validate_new_user(username, password):
    """Текст ошибки или None."""
    return validate_username(username) or validate_password(password)


def min_password_len(admin=False):
    return ADMIN_MIN_PASSWORD_LEN if admin else MIN_PASSWORD_LEN


def validate_password(password, admin=False):
    if len(password) < min_password_len(admin):
        return f"Пароль должен быть не короче {min_password_len(admin)} символов."
    return None


def create_user(username, password, full_name=""):
    conn = get_db()
    conn.execute("INSERT INTO users (username, full_name, password_hash, created_at, must_change_password) "
                 "VALUES (?, ?, ?, ?, 1)",
                 (username, full_name, generate_password_hash(password), date.today().isoformat()))
    conn.commit()


def delete_user(conn, user_id):
    # Заявки удалённого пользователя остаются (с его именем), но больше ни к кому не привязаны.
    conn.execute("UPDATE tickets SET author_id = NULL WHERE author_id = ?", (user_id,))
    conn.execute("UPDATE ticket_messages SET author_id = NULL WHERE author_id = ?", (user_id,))
    conn.execute("DELETE FROM ticket_watchers WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()


@app.route("/users")
@admin_required
def users_page():
    users = get_db().execute(
        """SELECT u.*, av.version AS avatar, (SELECT COUNT(*) FROM tickets t WHERE t.author_id = u.id) AS tickets
           FROM users u LEFT JOIN user_avatars av ON av.user_id = u.id
           ORDER BY u.username COLLATE NOCASE""").fetchall()
    return render_template("users.html", users=users, min_len=MIN_PASSWORD_LEN)


@app.route("/users/new", methods=["POST"])
@admin_required
def user_new():
    username, password = form_str("username", 60), request.form.get("password", "")
    error = validate_new_user(username, password)
    if error:
        flash(error, "danger")
    else:
        create_user(username, password, form_str("full_name"))
        app.logger.warning("user created: %s", username)
        flash(f"Пользователь «{username}» создан. Передайте ему логин и пароль — при первом входе он задаст свой.",
              "success")
    return redirect(url_for("users_page"))


def get_user_or_404(user_id):
    row = get_db().execute(USERS_SQL + " WHERE u.id = ?", (user_id,)).fetchone()
    if not row:
        abort(404)
    return row


def check_profile_access(user_id):
    """Менять профиль может администратор или сам пользователь."""
    me = current_user()
    if not (me["admin"] or me["id"] == user_id):
        abort(403)


AVATAR_SIZE = 256                    # сторона квадрата, px
AVATAR_MAX_BYTES = 10 * 1024 * 1024  # исходный файл; фото с телефона обычно 2–6 МБ
IMAGE_MAX_PIXELS = 50_000_000        # защита от «бомб»: маленький файл, огромная картинка


def pillow_available():
    """Pillow ставится из requirements.txt; без него сайт работает, но аватарки не загрузить."""
    import importlib.util
    return importlib.util.find_spec("PIL") is not None


def load_image(data):
    """Байты загруженной картинки -> RGB-картинка Pillow, повёрнутая как снято. ValueError — если это не картинка.
    Дальше картинка всегда пересохраняется заново, поэтому метаданные фото (в том числе GPS) не сохраняются."""
    import warnings
    from PIL import Image, ImageOps  # Pillow нужен только для картинок
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            img = Image.open(io.BytesIO(data))
            if img.width * img.height > IMAGE_MAX_PIXELS:
                raise ValueError("слишком большое разрешение")
            img = ImageOps.exif_transpose(img)  # фото с телефона — повернуть как снято
            if img.mode in ("RGBA", "LA", "PA") or (img.mode == "P" and "transparency" in img.info):
                img = img.convert("RGBA")
                bg = Image.new("RGB", img.size, "white")
                bg.paste(img, mask=img.getchannel("A"))
                return bg
            return img.convert("RGB")
    except (OSError, SyntaxError, ValueError, Image.DecompressionBombError, Image.DecompressionBombWarning) as e:
        raise ValueError(str(e)) from e


def to_jpeg(img, quality=88):
    out = io.BytesIO()
    img.save(out, "JPEG", quality=quality, optimize=True)
    return out.getvalue()


def make_avatar(data):
    """Байты загруженной картинки -> квадратный JPEG AVATAR_SIZE px. ValueError — если это не картинка."""
    from PIL import Image, ImageOps
    return to_jpeg(ImageOps.fit(load_image(data), (AVATAR_SIZE, AVATAR_SIZE), Image.LANCZOS))


@app.route("/users/<int:user_id>/avatar")
def user_avatar(user_id):
    row = get_db().execute("SELECT image FROM user_avatars WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        abort(404)
    resp = Response(row["image"], mimetype="image/jpeg")
    # В ссылке есть версия (?v=), поэтому картинку можно надолго оставить в кэше браузера.
    resp.headers["Cache-Control"] = "private, max-age=31536000, immutable"
    return resp


@app.route("/users/<int:user_id>/avatar", methods=["POST"])
def user_avatar_upload(user_id):
    check_profile_access(user_id)
    get_user_or_404(user_id)
    file = request.files.get("avatar")
    data = file.read(AVATAR_MAX_BYTES + 1) if file and file.filename else b""
    if not pillow_available():
        app.logger.error("avatar upload: Pillow is not installed, run pip install -r requirements.txt")
        flash("Загрузка аватарок пока не работает: на сервере не установлена библиотека Pillow. "
              "Сообщите администратору.", "danger")
    elif not data:
        flash("Выберите файл с фотографией.", "danger")
    elif len(data) > AVATAR_MAX_BYTES:
        flash(f"Файл больше {AVATAR_MAX_BYTES // 1024 // 1024} МБ — выберите фото поменьше.", "danger")
    else:
        try:
            image = make_avatar(data)
        except ValueError as e:
            app.logger.warning("avatar rejected: user_id=%s: %s", user_id, e)
            flash("Не получилось открыть файл как картинку. Подойдут JPG, PNG, WEBP или GIF.", "danger")
        else:
            conn = get_db()
            conn.execute("INSERT OR REPLACE INTO user_avatars (user_id, image, version) VALUES (?, ?, ?)",
                         (user_id, image, secrets.token_hex(6)))
            conn.commit()
            flash("Аватарка обновлена.", "success")
    return redirect(url_for("user_profile", user_id=user_id))


@app.route("/users/<int:user_id>/avatar/delete", methods=["POST"])
def user_avatar_delete(user_id):
    check_profile_access(user_id)
    conn = get_db()
    conn.execute("DELETE FROM user_avatars WHERE user_id = ?", (user_id,))
    conn.commit()
    flash("Аватарка удалена.", "info")
    return redirect(url_for("user_profile", user_id=user_id))


@app.route("/users/<int:user_id>", methods=["GET", "POST"])
def user_profile(user_id):
    """Профиль пользователя. Смотреть могут все вошедшие (заявки и так видны всем).
    Администратор меняет логин и имя, сам пользователь — только своё имя."""
    user = get_user_or_404(user_id)
    me = current_user()
    is_self = me["id"] == user_id
    form = dict(username=user["username"], full_name=user["full_name"])
    if request.method == "POST":
        check_profile_access(user_id)
        form["full_name"] = form_str("full_name")
        if me["admin"]:
            form["username"] = form_str("username", 60)
        error = validate_username(form["username"], user_id)
        if error:
            flash(error, "danger")
        else:
            conn = get_db()
            conn.execute("UPDATE users SET username = ?, full_name = ? WHERE id = ?",
                         (form["username"], form["full_name"], user_id))
            # Автор в заявках показывается по профилю; в переписке остаются имена на момент сообщения.
            conn.execute("UPDATE tickets SET author_username = ?, author_name = ? WHERE author_id = ?",
                         (form["username"], form["full_name"] or form["username"], user_id))
            conn.commit()
            if form["username"] != user["username"]:
                app.logger.warning("user renamed: %s -> %s", user["username"], form["username"])
            flash("Профиль сохранён." + (f" Новый логин для входа — «{form['username']}»."
                                          if form["username"] != user["username"] else ""), "success")
            return redirect(url_for("user_profile", user_id=user_id))
    tickets = [ticket_dict(r) for r in get_db().execute(
        TICKETS_SQL + " WHERE t.author_id = ? ORDER BY t.status IN ('done', 'rejected'), t.updated_at DESC, t.id DESC",
        (me["id"], user_id))]
    return render_template("user_profile.html", user=user, form=form, tickets=tickets, is_self=is_self,
                           min_len=MIN_PASSWORD_LEN, avatars_ok=pillow_available())


@app.route("/users/<int:user_id>/password", methods=["POST"])
@admin_required
def user_password(user_id):
    back = url_for("user_profile", user_id=user_id) if request.form.get("back") == "edit" else url_for("users_page")
    password = request.form.get("password", "")
    error = validate_password(password)
    if error:
        flash(error, "danger")
        return redirect(back)
    conn = get_db()
    cur = conn.execute("UPDATE users SET password_hash = ?, must_change_password = 1, reset_requested_at = '' "
                       "WHERE id = ?", (generate_password_hash(password), user_id))
    conn.commit()
    if not cur.rowcount:
        abort(404)
    flash("Пароль изменён, открытые сессии пользователя закрыты. При входе он задаст свой пароль.", "success")
    return redirect(back)


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def user_delete(user_id):
    conn = get_db()
    row = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        abort(404)
    delete_user(conn, user_id)
    app.logger.warning("user deleted: %s", row["username"])
    flash(f"Пользователь «{row['username']}» удалён, его сессии закрыты.", "info")
    return redirect(url_for("users_page"))


@app.route("/account", methods=["GET", "POST"])
def account():
    """Смена собственного пароля. У пользователя форма — в его профиле, у администратора профиля нет.
    Если пароль выдал администратор, пользователь попадает сюда, пока не задаст свой."""
    user = current_user()
    forced = bool(user.get("must_change"))
    # Пользователь меняет пароль в профиле; отдельная страница — только когда смена обязательна.
    back = None if user["admin"] or forced else url_for("user_profile", user_id=user["id"])
    if back and request.method == "GET":
        return redirect(back)
    if request.method == "POST":
        conn = get_db()
        ip = client_ip()
        now = time.time()
        conn.execute("DELETE FROM login_failures WHERE ts < ?", (now - LOGIN_WINDOW,))
        if conn.execute("SELECT COUNT(*) FROM login_failures WHERE ip = ?", (ip,)).fetchone()[0] \
                >= LOGIN_MAX_FAILURES:
            conn.commit()
            flash(f"Слишком много неудачных попыток. Повторите через {LOGIN_WINDOW // 60} минут.", "danger")
            if back:
                return redirect(back)
            return render_template("account.html", min_len=min_password_len(user["admin"]), forced=forced), 429
        if user["admin"]:
            old_hash = get_setting_safe("admin_password")
        else:
            old_hash = conn.execute("SELECT password_hash FROM users WHERE id = ?",
                                    (user["id"],)).fetchone()[0]
        current, new, confirm = (request.form.get(k, "") for k in ("current", "new", "confirm"))
        if not check_password_hash(old_hash, current):
            # Неверный текущий пароль считается неудачной попыткой входа — защита от подбора.
            conn.execute("INSERT INTO login_failures (ip, ts) VALUES (?, ?)", (ip, now))
            conn.commit()
            app.logger.warning("password change failed: user=%s ip=%s", user["username"], ip)
            time.sleep(1)
            flash("Текущий пароль указан неверно.", "danger")
        elif new != confirm:
            flash("Новый пароль и подтверждение не совпадают.", "danger")
        elif new == current:
            flash("Новый пароль совпадает с текущим.", "danger")
        elif validate_password(new, user["admin"]):
            flash(validate_password(new, user["admin"]), "danger")
        else:
            new_hash = generate_password_hash(new)
            if user["admin"]:
                db.set_setting("admin_password", new_hash)
            else:
                conn.execute("UPDATE users SET password_hash = ?, must_change_password = 0, reset_requested_at = '' "
                             "WHERE id = ?", (new_hash, user["id"]))
                conn.commit()
            # Текущая сессия остаётся, остальные сессии этого пользователя закрываются.
            session["pwm"] = password_marker(new_hash)
            app.logger.warning("password changed: user=%s ip=%s", user["username"], ip)
            if forced:
                flash("Пароль сохранён. Теперь входите с ним.", "success")
                return redirect(url_for("index"))
            flash("Пароль изменён. На других устройствах нужно будет войти заново.", "success")
            return redirect(url_for("account"))
        if back:
            return redirect(back)
    return render_template("account.html", min_len=min_password_len(user["admin"]), forced=forced)


FORGOT_MAX_PER_IP = 5            # нажатий «Забыли пароль?» с одного адреса за час
FORGOT_REPEAT = 30 * 60          # повторное уведомление об одном пользователе — не чаще, сек


def site_url_for(endpoint, **values):
    """Полная ссылка для Telegram: адрес сайта из настроек или тот, по которому зашли."""
    base = db.get_setting("site_url", "") or request.url_root
    return base.rstrip("/") + url_for(endpoint, **values)


@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    """«Забыли пароль?» — администратор получает уведомление и сам выдаёт новый пароль.
    Ответ одинаковый, есть такой логин или нет, — чтобы по нему нельзя было подбирать логины."""
    if current_user():
        return redirect(url_for("index"))
    if request.method == "POST":
        conn = get_db()
        ip, now = client_ip(), time.time()
        conn.execute("DELETE FROM forgot_requests WHERE ts < ?", (now - 3600,))
        if conn.execute("SELECT COUNT(*) FROM forgot_requests WHERE ip = ?", (ip,)).fetchone()[0] \
                >= FORGOT_MAX_PER_IP:
            conn.commit()
            flash("Слишком много запросов. Попробуйте через час или свяжитесь с администратором напрямую.", "danger")
            return render_template("forgot.html"), 429
        conn.execute("INSERT INTO forgot_requests (ip, ts) VALUES (?, ?)", (ip, now))
        username = form_str("username", 60)
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone() if username else None
        app.logger.warning("forgot password: user=%s found=%s ip=%s", username[:50], bool(row), ip)
        if row:
            last = row["reset_requested_at"]
            repeat = last and time.time() - time.mktime(time.strptime(last, "%Y-%m-%d %H:%M")) < FORGOT_REPEAT
            conn.execute("UPDATE users SET reset_requested_at = ? WHERE id = ?", (now_str(), row["id"]))
            if not repeat:
                from html import escape
                name = row["full_name"] or row["username"]
                notify_admin(f"🔑 <b>Забыл пароль:</b> {escape(name)} (логин <code>{escape(row['username'])}</code>)\n"
                             f"Задайте новый пароль в профиле и сообщите его:\n"
                             f"{site_url_for('user_profile', user_id=row['id'])}")
        conn.commit()
        return render_template("forgot.html", sent=True)
    return render_template("forgot.html")


@app.cli.command("add-user")
@click.argument("username")
@click.option("--name", "full_name", default="", help="Имя (ФИО) — так пользователь показывается на сайте.")
@click.password_option(prompt="Пароль пользователя")
def add_user_command(username, full_name, password):
    """Добавить пользователя с правом просмотра."""
    error = validate_new_user(username, password)
    if error:
        raise click.ClickException(error)
    create_user(username, password, full_name)
    click.echo(f"Готово. Пользователь {username} может входить для просмотра.")


@app.cli.command("del-user")
@click.argument("username")
def del_user_command(username):
    """Удалить пользователя с правом просмотра."""
    row = get_db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        raise click.ClickException(f"Пользователь «{username}» не найден.")
    delete_user(get_db(), row["id"])
    click.echo(f"Пользователь {username} удалён.")


@app.cli.command("init-db")
def init_db_command():
    """Создать таблицы (выполняется и автоматически при запуске)."""
    db.init_db()
    click.echo("База готова: " + app.config["DATABASE"])


# --------------------------------------------------------------------------- helpers

def form_str(name, maxlen=200):
    return request.form.get(name, "").strip()[:maxlen]


def form_int(name):
    try:
        return int(request.form.get(name, "").strip())
    except ValueError:
        return None


def form_date(name):
    value = request.form.get(name, "").strip()
    if not value:
        return ""
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        return None


def get_auditorium_or_404(code):
    num = parse_aud_code(code)
    row = num and get_db().execute("SELECT * FROM auditoriums WHERE num = ?", (num,)).fetchone()
    if not row:
        abort(404)
    return row


def get_computer_or_404(hostname):
    parsed = parse_hostname(hostname)
    row = parsed and get_db().execute(
        COMPUTERS_SQL + " WHERE a.num = ? AND c.num = ?", parsed).fetchone()
    if not row:
        abort(404)
    return computer_dict(row)


def get_software_or_404(sw_id):
    row = get_db().execute("SELECT * FROM software WHERE id = ?", (sw_id,)).fetchone()
    if not row:
        abort(404)
    return row


def list_auditoriums():
    return get_db().execute(
        """SELECT a.*, (SELECT COUNT(*) FROM computers c WHERE c.auditorium_id = a.id) AS pc_count
           FROM auditoriums a ORDER BY a.num""").fetchall()


def list_computers(where="", params=()):
    rows = get_db().execute(COMPUTERS_SQL + where + " ORDER BY a.num, c.num", params).fetchall()
    return [computer_dict(r) for r in rows]


def software_names():
    return [r["name"] for r in get_db().execute("SELECT name FROM software ORDER BY name")]


def find_or_create_software(name):
    """Возвращает (id, создано_ли)."""
    conn = get_db()
    row = conn.execute("SELECT id FROM software WHERE name = ?", (name,)).fetchone()
    if row:
        return row["id"], False
    cur = conn.execute("INSERT INTO software (name) VALUES (?)", (name,))
    return cur.lastrowid, True


@app.template_filter("ru_date")
def ru_date(value):
    if not value:
        return "—"
    try:
        return date.fromisoformat(value).strftime("%d.%m.%Y")
    except ValueError:
        return value


# --------------------------------------------------------------------------- dashboard

@app.route("/")
def index():
    conn = get_db()
    stats = {
        "auditoriums": conn.execute("SELECT COUNT(*) FROM auditoriums").fetchone()[0],
        "computers": conn.execute("SELECT COUNT(*) FROM computers").fetchone()[0],
        "software": conn.execute("SELECT COUNT(*) FROM software").fetchone()[0],
        "installations": conn.execute("SELECT COUNT(*) FROM installations").fetchone()[0],
    }
    top = conn.execute(
        """SELECT s.id, s.name, s.category, COUNT(i.id) AS cnt
           FROM software s JOIN installations i ON i.software_id = s.id
           GROUP BY s.id ORDER BY cnt DESC, s.name LIMIT 10""").fetchall()
    recent = conn.execute(
        """SELECT i.*, s.name AS sw_name, c.num AS pc_num, a.num AS aud_num
           FROM installations i JOIN software s ON s.id = i.software_id
           JOIN computers c ON c.id = i.computer_id JOIN auditoriums a ON a.id = c.auditorium_id
           WHERE i.installed_at != '' ORDER BY i.installed_at DESC, i.id DESC LIMIT 10""").fetchall()
    last_import = conn.execute("SELECT * FROM imports ORDER BY id DESC LIMIT 1").fetchone()
    # Открытые заявки: сначала с новыми сообщениями для смотрящего, потом недавно обновлённые.
    open_tickets = [ticket_dict(r) for r in conn.execute(
        TICKETS_SQL + " WHERE t.status IN (%s) ORDER BY t.updated_at DESC, t.id DESC"
        % ",".join("?" * len(TICKET_OPEN)), (current_user()["id"], *TICKET_OPEN))]
    open_tickets.sort(key=lambda t: not t["unread"])
    computers = list_computers()
    for c in computers:
        c["ip"] = netmap.ip_from_note(c["note"])
        c["wol"] = c["status"] != "decommissioned" and bool(netmap.macs_from_note(c["note"]))
    return render_template("index.html", stats=stats, top=top, recent=recent,
                           auditoriums=list_auditoriums(), computers=computers, pc_hostname=pc_hostname,
                           last_import=last_import, open_tickets=open_tickets)


def wake_computers(computers):
    """Wake-on-LAN для списка ПК (списанные пропускаются). -> (имена разбуженных, имена ПК без MAC)."""
    woken, no_mac = [], []
    for c in computers:
        if c["status"] == "decommissioned":
            continue
        macs = netmap.macs_from_note(c["note"])
        if macs and netmap.wake(macs, netmap.ip_from_note(c["note"])):
            woken.append(c["hostname"])
        else:
            no_mac.append(c["hostname"])
    if woken:
        app.logger.warning("wol: %s (by %s, ip=%s)", ", ".join(woken), current_user()["username"] or "admin",
                           request.remote_addr)
    return woken, no_mac


INSTANCE_DIR = os.path.dirname(app.config["DATABASE"])


def shutdown_account():
    return shutdown.load_account(INSTANCE_DIR)


@app.context_processor
def shutdown_context():
    return {"shutdown_ready": is_admin() and bool(shutdown_account())}


def shutdown_computers(computers):
    """Выключить ПК, которые сейчас в сети. Адрес — только проверенный блоком «ПК в сети» (ответил именно этот ПК),
    чтобы по устаревшей записи DNS не выключить чужой компьютер. -> (выключаются, не в сети, {имя: ошибка})."""
    computers = [c for c in computers if c["status"] != "decommissioned"]
    up, _at, error, _details = netmap.status(computers)
    if error:
        return [], [], {c["hostname"]: error for c in computers}
    offline = [c["hostname"] for c in computers if c["hostname"] not in up]
    results = shutdown.shutdown_many([up[h]["ip"] for h in up], INSTANCE_DIR)
    started, failed = [], {}
    for host, info in up.items():
        ok, text = results[info["ip"]]
        if ok:
            started.append(host)
        else:
            failed[host] = text
    who = (current_user()["username"] or "admin", request.remote_addr) if has_request_context() else ("cli", "-")
    if started:
        app.logger.warning("shutdown: %s (by %s, ip=%s)", ", ".join(sorted(started)), *who)
    for host, text in failed.items():
        app.logger.warning("shutdown failed: %s: %s", host, text)
    return sorted(started), offline, failed


def flash_shutdown(started, offline, failed, label):
    if started == [label]:
        flash(f"{label}: выключение запущено. Пользователь увидит предупреждение, через минуту ПК выключится.", "success")
    elif started:
        flash(f"{label}: выключение запущено на {len(started)} ПК ({', '.join(started)}). "
              f"Пользователи увидят предупреждение, через минуту ПК выключатся.", "success")
    for host, text in sorted(failed.items()):
        flash(f"{host}: не удалось выключить — {text}.", "danger")
    if offline and not started and not failed:
        flash(f"{label}: выключать нечего — {'ПК не в сети' if len(offline) == 1 else 'ни один ПК не в сети'}.", "info")
    elif offline and (started or failed):
        flash(f"Не в сети, пропущены: {', '.join(offline)}.", "info")


@app.route("/computers/<hostname>/shutdown", methods=["POST"])
@admin_required
def computer_shutdown(hostname):
    pc = get_computer_or_404(hostname)
    if not shutdown_account():
        flash("Сначала задайте учётную запись для выключения — см. «Данные» → «Выключение ПК».", "warning")
    elif pc["status"] == "decommissioned":
        flash("Компьютер списан.", "warning")
    else:
        flash_shutdown(*shutdown_computers([pc]), pc["hostname"])
    return wake_redirect(url_for("computer", hostname=pc["hostname"]))


@app.route("/auditoriums/<code>/shutdown", methods=["POST"])
@admin_required
def auditorium_shutdown(code):
    aud = get_auditorium_or_404(code)
    code = aud_code(aud["num"])
    if not shutdown_account():
        flash("Сначала задайте учётную запись для выключения — см. «Данные» → «Выключение ПК».", "warning")
    else:
        flash_shutdown(*shutdown_computers(list_computers(" WHERE c.auditorium_id = ?", (aud["id"],))), code)
    return wake_redirect(url_for("auditorium", code=code))


@app.cli.command("set-shutdown-account")
@click.option("--domain", prompt="Домен (например TOP)", default="", show_default=False)
@click.option("--username", prompt="Логин учётной записи с правами администратора на ПК")
@click.password_option("--password", prompt="Пароль", confirmation_prompt="Ещё раз")
def set_shutdown_account_command(domain, username, password):
    """Учётная запись для выключения ПК (хранится в instance/shutdown.auth, не в базе)."""
    shutdown.save_account(INSTANCE_DIR, domain.strip(), username.strip(), password)
    click.echo(f"Сохранено: {domain.strip() + chr(92) if domain.strip() else ''}{username.strip()} "
               f"в {shutdown.auth_path(INSTANCE_DIR)}")


@app.cli.command("del-shutdown-account")
def del_shutdown_account_command():
    """Удалить учётную запись для выключения ПК."""
    click.echo("Удалено." if shutdown.delete_account(INSTANCE_DIR) else "Учётная запись не была задана.")


@app.cli.command("shutdown-check")
@click.argument("hostname")
def shutdown_check_command(hostname):
    """Проверить выключение на одном ПК. ПК действительно выключится (через минуту, с предупреждением)."""
    pc = get_computer_or_404(hostname)
    started, offline, failed = shutdown_computers([pc])
    click.echo("Выключение запущено." if started else "ПК не в сети." if offline else f"Ошибка: {failed.get(pc['hostname'])}")


def wake_redirect(default):
    """Назад туда, откуда нажали «Включить»/«Выключить»: на главную или на страницу ПК/аудитории."""
    return redirect(url_for("index") + "#netmap" if request.form.get("back") == "home" else default)


@app.route("/computers/<hostname>/wake", methods=["POST"])
@admin_required
def computer_wake(hostname):
    pc = get_computer_or_404(hostname)
    if pc["status"] == "decommissioned":
        flash("Компьютер списан.", "warning")
    else:
        woken, _ = wake_computers([pc])
        if woken:
            flash(f"{pc['hostname']}: команда на включение отправлена. Загрузка займёт 1–2 минуты.", "success")
        else:
            flash(f"У {pc['hostname']} неизвестен MAC-адрес: впишите «MAC: …» в примечание.", "warning")
    return wake_redirect(url_for("computer", hostname=pc["hostname"]))


@app.route("/auditoriums/<code>/wake", methods=["POST"])
@admin_required
def auditorium_wake(code):
    aud = get_auditorium_or_404(code)
    woken, no_mac = wake_computers(list_computers(" WHERE c.auditorium_id = ?", (aud["id"],)))
    code = aud_code(aud["num"])
    if woken:
        flash(f"{code}: команда на включение отправлена на {len(woken)} ПК. Загрузка займёт 1–2 минуты.", "success")
    if no_mac:
        flash(f"Без MAC-адреса, не включены: {', '.join(no_mac)}.", "warning")
    if not woken and not no_mac:
        flash(f"В {code} нет компьютеров для включения.", "info")
    return wake_redirect(url_for("auditorium", code=code))


@app.route("/api/netmap")
def netmap_status():
    """Какие ПК отвечают на ping: {hostname: "up" | "down" | "noip" | "off"}. Списанные не пингуются."""
    computers = list_computers()
    up, checked_at, error, details = netmap.status(computers)
    pcs = {}
    for c in computers:
        host = c["hostname"]
        if c["status"] == "decommissioned":
            pcs[host] = {"state": "off"}
        elif host not in details:
            pcs[host] = {"state": "noip"}
        elif error:
            pcs[host] = {"state": "wait"}  # неизвестно: сервер не смог пинговать
        elif host in up:
            pcs[host] = {"state": "up", **up[host]}
        else:
            pcs[host] = {"state": "down"}
    resp = jsonify(checked_at=datetime.fromtimestamp(checked_at).strftime("%H:%M:%S"), pcs=pcs, error=error)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------- auditoriums

@app.route("/auditoriums")
def auditoriums():
    return render_template("auditoriums.html", auditoriums=list_auditoriums(),
                           computers=list_computers())


@app.route("/auditoriums/new", methods=["POST"])
@admin_required
def auditorium_new():
    num = form_int("num")
    if not num or num < 1:
        flash("Укажите номер аудитории (целое число больше нуля).", "danger")
        return redirect(url_for("auditoriums"))
    try:
        get_db().execute("INSERT INTO auditoriums (num, floor, note) VALUES (?, ?, ?)",
                         (num, form_int("floor"), form_str("note", 500)))
        get_db().commit()
    except sqlite3.IntegrityError:
        flash(f"Аудитория {aud_code(num)} уже существует.", "danger")
        return redirect(url_for("auditoriums"))
    flash(f"Аудитория {aud_code(num)} добавлена.", "success")
    return redirect(url_for("auditorium", code=aud_code(num)))


@app.route("/auditoriums/<code>")
def auditorium(code):
    aud = get_auditorium_or_404(code)
    computers = list_computers(" WHERE c.auditorium_id = ?", (aud["id"],))
    # Открытые заявки на всю аудиторию и на её компьютеры.
    open_tickets = [ticket_dict(r) for r in get_db().execute(
        TICKETS_SQL + " WHERE COALESCE(c.auditorium_id, t.auditorium_id) = ? AND t.status IN (%s) ORDER BY t.id DESC"
        % ",".join("?" * len(TICKET_OPEN)), (current_user()["id"], aud["id"], *TICKET_OPEN))]
    return render_template("auditorium.html", aud=aud, code=aud_code(aud["num"]), computers=computers,
                           open_tickets=open_tickets)


@app.route("/auditoriums/<code>/edit", methods=["POST"])
@admin_required
def auditorium_edit(code):
    aud = get_auditorium_or_404(code)
    get_db().execute("UPDATE auditoriums SET floor = ?, note = ? WHERE id = ?",
                     (form_int("floor"), form_str("note", 500), aud["id"]))
    get_db().commit()
    flash("Сохранено.", "success")
    return redirect(url_for("auditorium", code=code))


@app.route("/auditoriums/<code>/delete", methods=["POST"])
@admin_required
def auditorium_delete(code):
    aud = get_auditorium_or_404(code)
    try:
        get_db().execute("DELETE FROM auditoriums WHERE id = ?", (aud["id"],))
        get_db().commit()
    except sqlite3.IntegrityError:
        flash("Нельзя удалить аудиторию, в которой есть компьютеры. Сначала перенесите или удалите их.", "danger")
        return redirect(url_for("auditorium", code=code))
    flash(f"Аудитория {code} удалена.", "success")
    return redirect(url_for("auditoriums"))


# --------------------------------------------------------------------------- computers

@app.route("/computers")
def computers():
    where, params = [], []
    aud = request.args.get("aud", "")
    status = request.args.get("status", "")
    if parse_aud_code(aud):
        where.append("a.num = ?")
        params.append(parse_aud_code(aud))
    if status in STATUSES:
        where.append("c.status = ?")
        params.append(status)
    sql = (" WHERE " + " AND ".join(where)) if where else ""
    return render_template("computers.html", computers=list_computers(sql, params),
                           auditoriums=list_auditoriums(), aud=aud, status=status)


def save_computer(existing=None):
    """Общая обработка формы создания/редактирования ПК. Возвращает hostname или None."""
    aud_id, num = form_int("auditorium_id"), form_int("num")
    errors = []
    aud_row = aud_id and get_db().execute("SELECT * FROM auditoriums WHERE id = ?", (aud_id,)).fetchone()
    if not aud_row:
        errors.append("Выберите аудиторию.")
    if not num or not 1 <= num <= 99:
        errors.append("Номер ПК — число от 1 до 99.")
    status = request.form.get("status", "active")
    if status not in STATUSES:
        status = "active"
    if errors:
        for e in errors:
            flash(e, "danger")
        return None
    fields = (aud_id, num, form_str("inv_number"), form_str("os"), form_str("os_version"),
              form_str("cpu"), form_str("ram"), form_str("disk"), status, form_str("note", 1000))
    conn = get_db()
    try:
        if existing:
            conn.execute("""UPDATE computers SET auditorium_id=?, num=?, inv_number=?, os=?, os_version=?,
                            cpu=?, ram=?, disk=?, status=?, note=? WHERE id=?""", fields + (existing["id"],))
        else:
            conn.execute("""INSERT INTO computers (auditorium_id, num, inv_number, os, os_version,
                            cpu, ram, disk, status, note) VALUES (?,?,?,?,?,?,?,?,?,?)""", fields)
        conn.commit()
    except sqlite3.IntegrityError:
        flash(f"{pc_hostname(aud_row['num'], num)} уже существует.", "danger")
        return None
    return pc_hostname(aud_row["num"], num)


@app.route("/computers/new", methods=["GET", "POST"])
@admin_required
def computer_new():
    if request.method == "POST":
        hostname = save_computer()
        if hostname:
            flash(f"{hostname} добавлен.", "success")
            if request.form.get("add_another"):
                return redirect(url_for("computer_new", aud=request.form.get("auditorium_id"),
                                        copy=hostname))
            return redirect(url_for("computer", hostname=hostname))
    # Предзаполнение: аудитория из ?aud=, характеристики из ?copy=PC-..
    pc = dict(request.form) if request.method == "POST" else {}
    if request.method == "GET":
        copy = request.args.get("copy")
        if copy and parse_hostname(copy):
            src = get_computer_or_404(copy)
            pc = {k: src[k] for k in ("auditorium_id", "os", "os_version", "cpu", "ram", "disk")}
            pc["num"] = src["num"] + 1
        elif request.args.get("aud", "").isdigit():
            pc["auditorium_id"] = int(request.args["aud"])
        if "num" not in pc and pc.get("auditorium_id"):
            nxt = get_db().execute("SELECT COALESCE(MAX(num), 0) + 1 FROM computers WHERE auditorium_id = ?",
                                   (pc["auditorium_id"],)).fetchone()[0]
            pc["num"] = nxt
    return render_template("computer_form.html", pc=pc, auditoriums=list_auditoriums(), is_new=True)


@app.route("/computers/<hostname>")
def computer(hostname):
    pc = get_computer_or_404(hostname)
    installs = get_db().execute(
        """SELECT i.*, s.name, s.vendor, s.category, s.license_type
           FROM installations i JOIN software s ON s.id = i.software_id
           WHERE i.computer_id = ? ORDER BY s.category, s.name""", (pc["id"],)).fetchall()
    open_tickets = get_db().execute(
        "SELECT * FROM tickets WHERE (computer_id = ? OR id IN "
        "(SELECT ticket_id FROM ticket_computers WHERE computer_id = ?)) AND status IN (%s) ORDER BY id DESC"
        % ",".join("?" * len(TICKET_OPEN)), (pc["id"], pc["id"], *TICKET_OPEN)).fetchall()
    return render_template("computer.html", pc=pc, installs=installs, sw_names=software_names(),
                           open_tickets=open_tickets, pc_macs=netmap.macs_from_note(pc["note"]))


@app.route("/computers/<hostname>/edit", methods=["GET", "POST"])
@admin_required
def computer_edit(hostname):
    pc = get_computer_or_404(hostname)
    if request.method == "POST":
        new_hostname = save_computer(pc)
        if new_hostname:
            flash("Сохранено.", "success")
            return redirect(url_for("computer", hostname=new_hostname))
        pc = {**pc, **request.form}
    return render_template("computer_form.html", pc=pc, auditoriums=list_auditoriums(), is_new=False)


@app.route("/computers/<hostname>/delete", methods=["POST"])
@admin_required
def computer_delete(hostname):
    pc = get_computer_or_404(hostname)
    get_db().execute("DELETE FROM computers WHERE id = ?", (pc["id"],))
    get_db().commit()
    flash(f"{pc['hostname']} удалён вместе со списком его ПО.", "success")
    return redirect(url_for("auditorium", code=pc["aud_code"]))


@app.route("/computers/<hostname>/install", methods=["POST"])
@admin_required
def computer_install(hostname):
    pc = get_computer_or_404(hostname)
    name = form_str("software")
    installed_at = form_date("installed_at")
    if not name:
        flash("Укажите название программы.", "danger")
    elif installed_at is None:
        flash("Неверная дата.", "danger")
    else:
        sw_id, created = find_or_create_software(name)
        conn = get_db()
        conn.execute(
            """INSERT INTO installations (computer_id, software_id, version, installed_at, note)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(computer_id, software_id) DO UPDATE SET
                 version = excluded.version, installed_at = excluded.installed_at, note = excluded.note""",
            (pc["id"], sw_id, form_str("version", 100), installed_at, form_str("note", 500)))
        conn.commit()
        flash(f"«{name}» записано на {pc['hostname']}.", "success")
        if created:
            flash(f"«{name}» — новая программа в справочнике. Заполните производителя и категорию.", "info")
    return redirect(url_for("computer", hostname=hostname))


@app.route("/installations/<int:inst_id>/edit", methods=["GET", "POST"])
@admin_required
def installation_edit(inst_id):
    conn = get_db()
    inst = conn.execute(
        """SELECT i.*, s.name, c.num AS pc_num, a.num AS aud_num FROM installations i
           JOIN software s ON s.id = i.software_id JOIN computers c ON c.id = i.computer_id
           JOIN auditoriums a ON a.id = c.auditorium_id WHERE i.id = ?""", (inst_id,)).fetchone()
    if not inst:
        abort(404)
    hostname = pc_hostname(inst["aud_num"], inst["pc_num"])
    if request.method == "POST":
        installed_at = form_date("installed_at")
        if installed_at is None:
            flash("Неверная дата.", "danger")
        else:
            conn.execute("UPDATE installations SET version = ?, installed_at = ?, note = ? WHERE id = ?",
                         (form_str("version", 100), installed_at, form_str("note", 500), inst_id))
            conn.commit()
            flash("Сохранено.", "success")
            return redirect(request.form.get("back") or url_for("computer", hostname=hostname))
    back = request.args.get("back", "")
    if not back.startswith("/") or back.startswith("//"):
        back = url_for("computer", hostname=hostname)
    return render_template("installation_form.html", inst=inst, hostname=hostname, back=back)


@app.route("/installations/<int:inst_id>/delete", methods=["POST"])
@admin_required
def installation_delete(inst_id):
    conn = get_db()
    conn.execute("DELETE FROM installations WHERE id = ?", (inst_id,))
    conn.commit()
    flash("Запись об установке удалена.", "success")
    back = request.form.get("back", "")
    return redirect(back if back.startswith("/") and not back.startswith("//") else url_for("index"))


# --------------------------------------------------------------------------- software

@app.route("/software")
def software_list():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "")
    license_type = request.args.get("license", "")
    where, params = [], []
    if q:
        where.append("(s.name LIKE ? OR s.vendor LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    if category in CATEGORIES:
        where.append("s.category = ?")
        params.append(category)
    if license_type in LICENSE_TYPES:
        where.append("s.license_type = ?")
        params.append(license_type)
    sql = """SELECT s.*, COUNT(i.id) AS cnt FROM software s
             LEFT JOIN installations i ON i.software_id = s.id"""
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " GROUP BY s.id ORDER BY s.name"
    items = get_db().execute(sql, params).fetchall()
    return render_template("software_list.html", items=items, q=q, category=category,
                           license_type=license_type)


def save_software(existing=None):
    name = form_str("name")
    if not name:
        flash("Укажите название.", "danger")
        return None
    category = request.form.get("category", "other")
    license_type = request.form.get("license_type", "free")
    url = form_str("url", 500)
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    fields = (name, form_str("vendor"), category if category in CATEGORIES else "other",
              license_type if license_type in LICENSE_TYPES else "free", url, form_str("note", 1000))
    conn = get_db()
    try:
        if existing:
            conn.execute("""UPDATE software SET name=?, vendor=?, category=?, license_type=?, url=?, note=?
                            WHERE id=?""", fields + (existing["id"],))
            sw_id = existing["id"]
        else:
            sw_id = conn.execute("""INSERT INTO software (name, vendor, category, license_type, url, note)
                                    VALUES (?,?,?,?,?,?)""", fields).lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        flash(f"Программа «{name}» уже есть в справочнике.", "danger")
        return None
    return sw_id


@app.route("/software/new", methods=["GET", "POST"])
@admin_required
def software_new():
    if request.method == "POST":
        sw_id = save_software()
        if sw_id:
            flash("Программа добавлена в справочник.", "success")
            return redirect(url_for("software", sw_id=sw_id))
    return render_template("software_form.html", sw=request.form, is_new=True)


@app.route("/software/<int:sw_id>")
def software(sw_id):
    sw = get_software_or_404(sw_id)
    rows = get_db().execute(
        """SELECT i.*, c.num AS pc_num, c.status, a.num AS aud_num
           FROM installations i JOIN computers c ON c.id = i.computer_id
           JOIN auditoriums a ON a.id = c.auditorium_id
           WHERE i.software_id = ? ORDER BY a.num, c.num""", (sw_id,)).fetchall()
    installs = [dict(r, hostname=pc_hostname(r["aud_num"], r["pc_num"])) for r in rows]
    versions = {}
    for r in installs:
        versions[r["version"] or "не указана"] = versions.get(r["version"] or "не указана", 0) + 1
    by_aud = {}
    for r in installs:
        by_aud.setdefault(aud_code(r["aud_num"]), []).append(r)
    return render_template("software.html", sw=sw, installs=installs, by_aud=by_aud,
                           versions=sorted(versions.items(), key=lambda kv: -kv[1]))


@app.route("/software/<int:sw_id>/edit", methods=["GET", "POST"])
@admin_required
def software_edit(sw_id):
    sw = get_software_or_404(sw_id)
    if request.method == "POST":
        if save_software(sw):
            flash("Сохранено.", "success")
            return redirect(url_for("software", sw_id=sw_id))
        sw = {**dict(sw), **request.form}
    return render_template("software_form.html", sw=sw, is_new=False)


@app.route("/software/<int:sw_id>/delete", methods=["POST"])
@admin_required
def software_delete(sw_id):
    sw = get_software_or_404(sw_id)
    get_db().execute("DELETE FROM software WHERE id = ?", (sw_id,))
    get_db().commit()
    flash(f"«{sw['name']}» удалена из справочника вместе со всеми установками.", "success")
    return redirect(url_for("software_list"))


@app.route("/software/<int:sw_id>/bulk", methods=["GET", "POST"])
@admin_required
def software_bulk(sw_id):
    """Массовая отметка: на каких ПК установлена программа."""
    sw = get_software_or_404(sw_id)
    conn = get_db()
    existing = {r["computer_id"]: r for r in conn.execute(
        "SELECT * FROM installations WHERE software_id = ?", (sw_id,))}
    if request.method == "POST":
        installed_at = form_date("installed_at")
        if installed_at is None:
            flash("Неверная дата.", "danger")
            return redirect(request.url)
        version = form_str("version", 100)
        selected = {int(x) for x in request.form.getlist("pc") if x.isdigit()}
        valid = {r["id"] for r in conn.execute("SELECT id FROM computers")}
        selected &= valid
        added = updated = removed = 0
        for pc_id in selected:
            if pc_id in existing:
                if request.form.get("overwrite"):
                    conn.execute("UPDATE installations SET version = ?, installed_at = ? WHERE id = ?",
                                 (version, installed_at, existing[pc_id]["id"]))
                    updated += 1
            else:
                conn.execute("""INSERT INTO installations (computer_id, software_id, version, installed_at)
                                VALUES (?, ?, ?, ?)""", (pc_id, sw_id, version, installed_at))
                added += 1
        if request.form.get("remove_unchecked"):
            for pc_id, inst in existing.items():
                if pc_id not in selected:
                    conn.execute("DELETE FROM installations WHERE id = ?", (inst["id"],))
                    removed += 1
        conn.commit()
        flash(f"Готово: добавлено {added}, обновлено {updated}, удалено {removed}.", "success")
        return redirect(url_for("software", sw_id=sw_id))
    groups = {}
    for pc in list_computers():
        groups.setdefault(pc["aud_code"], []).append(pc)
    return render_template("bulk.html", sw=sw, groups=groups, existing=existing)


# --------------------------------------------------------------------------- search

@app.route("/search")
def search():
    conn = get_db()
    sw_name = request.args.get("software", "").strip()
    mode = request.args.get("mode", "has")
    version = request.args.get("version", "").strip()
    aud = request.args.get("aud", "")
    results, sw = None, None
    if sw_name:
        sw = conn.execute("SELECT * FROM software WHERE name = ?", (sw_name,)).fetchone()
        if not sw:
            sw = conn.execute("SELECT * FROM software WHERE name LIKE ? ORDER BY name LIMIT 1",
                              (f"%{sw_name}%",)).fetchone()
    if sw:
        where, params = [], []
        if parse_aud_code(aud):
            where.append("a.num = ?")
            params.append(parse_aud_code(aud))
        inst_cond = "i.computer_id = c.id AND i.software_id = ?"
        inst_params = [sw["id"]]
        if version and mode == "has":
            inst_cond += " AND i.version LIKE ?"
            inst_params.append(f"{version}%")
        exists = f"EXISTS (SELECT 1 FROM installations i WHERE {inst_cond})"
        where.append(exists if mode == "has" else "NOT " + exists)
        params = params + inst_params
        results = list_computers(" WHERE " + " AND ".join(where), params)
        versions = {r["computer_id"]: r["version"] for r in conn.execute(
            "SELECT computer_id, version FROM installations WHERE software_id = ?", (sw["id"],))}
        for r in results:
            r["sw_version"] = versions.get(r["id"])
    elif sw_name:
        flash(f"Программа «{sw_name}» не найдена в справочнике.", "warning")
    return render_template("search.html", sw=sw, sw_name=sw_name, mode=mode, version=version,
                           aud=aud, results=results, sw_names=software_names(),
                           auditoriums=list_auditoriums())


# --------------------------------------------------------------------------- export / backup

def export_rows(kind):
    conn = get_db()
    if kind == "computers":
        header = ["Hostname", "Аудитория", "Инв. номер", "ОС", "Версия ОС", "CPU", "RAM", "Диск",
                  "Статус", "Кол-во ПО", "Примечание"]
        rows = [[c["hostname"], c["aud_code"], c["inv_number"], c["os"], c["os_version"], c["cpu"],
                 c["ram"], c["disk"], STATUSES.get(c["status"], c["status"]), c["sw_count"], c["note"]]
                for c in list_computers()]
    elif kind == "software":
        header = ["Название", "Производитель", "Категория", "Лицензия", "Сайт", "Установок", "Примечание"]
        rows = [[s["name"], s["vendor"], CATEGORIES.get(s["category"], s["category"]),
                 LICENSE_TYPES.get(s["license_type"], s["license_type"]), s["url"], s["cnt"], s["note"]]
                for s in conn.execute("""SELECT s.*, COUNT(i.id) AS cnt FROM software s
                     LEFT JOIN installations i ON i.software_id = s.id GROUP BY s.id ORDER BY s.name""")]
    elif kind == "installations":
        header = ["Аудитория", "Hostname", "Программа", "Производитель", "Категория", "Версия",
                  "Дата установки", "Примечание"]
        rows = [[aud_code(r["aud_num"]), pc_hostname(r["aud_num"], r["pc_num"]), r["name"], r["vendor"],
                 CATEGORIES.get(r["category"], r["category"]), r["version"], r["installed_at"], r["note"]]
                for r in conn.execute(
                    """SELECT i.*, s.name, s.vendor, s.category, c.num AS pc_num, a.num AS aud_num
                       FROM installations i JOIN software s ON s.id = i.software_id
                       JOIN computers c ON c.id = i.computer_id JOIN auditoriums a ON a.id = c.auditorium_id
                       ORDER BY a.num, c.num, s.name""")]
    else:
        abort(404)
    return header, rows


EXPORT_TITLES = {"computers": "Компьютеры", "software": "Справочник ПО", "installations": "Установки"}


@app.route("/export/<kind>.<fmt>")
def export(kind, fmt):
    if kind not in EXPORT_TITLES:
        abort(404)
    stamp = date.today().isoformat()
    if fmt == "csv":
        header, rows = export_rows(kind)
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=";")
        writer.writerow(header)
        writer.writerows(rows)
        # BOM, чтобы Excel правильно открыл кириллицу
        return Response("﻿" + buf.getvalue(), mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename={kind}-{stamp}.csv"})
    if fmt == "xlsx":
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
        from openpyxl.utils import get_column_letter
        wb = Workbook()
        wb.remove(wb.active)
        kinds = list(EXPORT_TITLES) if kind == "installations" else [kind]
        for k in kinds:
            header, rows = export_rows(k)
            ws = wb.create_sheet(EXPORT_TITLES[k])
            ws.append(header)
            for r in rows:
                ws.append(r)
            for cell in ws[1]:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = PatternFill("solid", fgColor="E8501A")
            ws.freeze_panes = "A2"
            ws.auto_filter.ref = ws.dimensions
            for i, col in enumerate(zip(header, *rows) if rows else [[h] for h in header], start=1):
                width = max(len(str(v or "")) for v in col)
                ws.column_dimensions[get_column_letter(i)].width = min(max(width + 2, 10), 60)
        if kind == "installations":
            wb.move_sheet(EXPORT_TITLES["installations"], offset=-2)
            wb.active = 0
        out = io.BytesIO()
        wb.save(out)
        out.seek(0)
        name = "registry" if kind == "installations" else kind
        return send_file(out, as_attachment=True, download_name=f"{name}-{stamp}.xlsx",
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    abort(404)


BACKUP_TABLES = ["auditoriums", "computers", "software", "installations", "sw_aliases",
                 "tickets", "ticket_computers", "ticket_messages", "ticket_watchers"]


@app.route("/data")
@admin_required
def data_page():
    token = db.get_setting("telegram_token", "")
    try:
        tg_backup = json.loads(db.get_setting("telegram_backup_last", "") or "null")
    except ValueError:
        tg_backup = None
    return render_template("data.html", tg_token_tail=token[-4:] if token else "",
                           tg_chat=db.get_setting("telegram_chat", ""), site_url=db.get_setting("site_url", ""),
                           tg_backup=tg_backup, shutdown_account=shutdown_account())


# --------------------------------------------------------------------------- копия в Telegram

TG_FILE_LIMIT = 49 * 1024 * 1024  # Bot API принимает файлы до 50 МБ
_tg_backup_lock = threading.Lock()


def human_size(n):
    return f"{n / 1024 / 1024:.1f} МБ" if n >= 1024 * 1024 else f"{max(1, round(n / 1024))} КБ"


def telegram_configured():
    return bool(db.get_setting("telegram_token", "") and db.get_setting("telegram_chat", ""))


def save_backup_status(ok, info):
    db.set_setting("telegram_backup_last", json.dumps(
        {"at": datetime.now().strftime("%d.%m.%Y %H:%M"), "ok": ok, "info": info}, ensure_ascii=False))


def send_backup_to_telegram():
    """Копия базы в Telegram, в чат уведомлений о заявках. -> «файл, размер»; ошибка — RuntimeError.

    Отправляется сама база registry.db (с фото и аватарками), сжатая gzip. Если она больше 50 МБ — JSON-копия.
    Результат запоминается в настройке telegram_backup_last, его видно на странице «Данные».
    """
    if not telegram_configured():
        raise RuntimeError("Telegram не настроен: укажите токен бота и chat id на странице «Данные».")
    if not _tg_backup_lock.acquire(blocking=False):
        raise RuntimeError("Копия уже отправляется, подождите.")
    try:
        token, chat = db.get_setting("telegram_token", ""), db.get_setting("telegram_chat", "")
        now = datetime.now()
        stamp, shown = now.strftime("%Y-%m-%d_%H-%M"), now.strftime("%d.%m.%Y %H:%M")
        conn = get_db()
        counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in ("computers", "software", "tickets", "users")}
        summary = (f"ПК: {counts['computers']}, программ: {counts['software']}, "
                   f"заявок: {counts['tickets']}, пользователей: {counts['users']}")
        # Согласованная копия работающей базы средствами SQLite, затем gzip.
        fd, tmp = tempfile.mkstemp(prefix="tg-backup-", suffix=".db", dir=os.path.dirname(app.config["DATABASE"]))
        os.close(fd)
        try:
            dest = sqlite3.connect(tmp)
            conn.backup(dest)
            dest.close()
            with open(tmp, "rb") as f:
                content = gzip.compress(f.read(), compresslevel=6)
        finally:
            os.remove(tmp)
        if len(content) <= TG_FILE_LIMIT:
            filename = f"registry-{stamp}.db.gz"
            caption = (f"💾 <b>{SITE_NAME}</b>: резервная копия базы на {shown}\n{summary}\n"
                       f"Как восстановить — в README, раздел «Резервные копии».")
        else:
            big = human_size(len(content))
            content = gzip.compress(backup_json().encode("utf-8"))
            filename = f"registry-backup-{stamp}.json.gz"
            caption = (f"💾 <b>{SITE_NAME}</b>: резервная копия на {shown}\n{summary}\n"
                       f"⚠️ База ({big}) больше 50 МБ, поэтому отправлена JSON-копия без пользователей, "
                       f"фото и аватарок. Полные копии — на сервере в /var/backups/registry.")
        try:
            telegram.send_document(token, chat, filename, content, caption)
        except RuntimeError as e:
            raise RuntimeError(f"Telegram: {e}") from None
        result = f"{filename}, {human_size(len(content))}"
        save_backup_status(True, result)
        app.logger.warning("telegram backup: sent %s", result)
        return result
    except Exception as e:
        save_backup_status(False, str(e))
        app.logger.error("telegram backup: %s", e)
        raise
    finally:
        _tg_backup_lock.release()


@app.cli.command("send-backup")
def send_backup_command():
    """Отправить копию базы в Telegram (её запускает таймер registry-backup.timer каждый день в 00:00)."""
    if not telegram_configured():
        click.echo("Telegram не настроен — копия не отправлена.")
        return
    try:
        click.echo(f"Отправлено: {send_backup_to_telegram()}")
    except Exception as e:
        try:  # если сам Telegram доступен, сообщим об ошибке туда же
            telegram.send(db.get_setting("telegram_token", ""), db.get_setting("telegram_chat", ""),
                          f"⚠️ {SITE_NAME}: не удалось отправить резервную копию: {e}")
        except RuntimeError:
            pass
        raise click.ClickException(str(e))


@app.route("/settings/telegram/backup", methods=["POST"])
@admin_required
def telegram_backup_now():
    """«Отправить копию сейчас» — в фоне, чтобы страница не ждала загрузку файла."""
    if not telegram_configured():
        flash("Сначала настройте Telegram: токен бота и chat id.", "danger")
        return redirect(url_for("data_page") + "#tg-backup")
    if _tg_backup_lock.locked():
        flash("Копия уже отправляется, подождите.", "info")
        return redirect(url_for("data_page") + "#tg-backup")

    def run():
        with app.app_context():
            try:
                send_backup_to_telegram()
            except Exception:
                pass  # ошибка уже записана в журнал и в статус на странице «Данные»

    threading.Thread(target=run, daemon=True).start()
    flash("Копия базы отправляется в Telegram. Обновите страницу через минуту — здесь появится результат.", "success")
    return redirect(url_for("data_page") + "#tg-backup")


def backup_json():
    """Копия данных в JSON (без пользователей, фото и аватарок) — та же, что «Скачать копию (JSON)»."""
    conn = get_db()
    payload = {"format": "top-software-registry", "version": 1, "created": date.today().isoformat()}
    for t in BACKUP_TABLES:
        payload[t] = [dict(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY rowid")]
    return json.dumps(payload, ensure_ascii=False, indent=1)


@app.route("/backup.json")
@admin_required
def backup():
    return Response(backup_json(), mimetype="application/json",
                    headers={"Content-Disposition":
                             f"attachment; filename=registry-backup-{date.today().isoformat()}.json"})


@app.route("/restore", methods=["POST"])
@admin_required
def restore():
    file = request.files.get("file")
    if not file or not request.form.get("confirm"):
        flash("Выберите файл и подтвердите замену данных.", "danger")
        return redirect(url_for("data_page"))
    try:
        payload = json.load(file)
        if payload.get("format") != "top-software-registry":
            raise ValueError("это не резервная копия реестра")
    except (ValueError, UnicodeDecodeError) as e:
        flash(f"Не удалось прочитать файл: {e}", "danger")
        return redirect(url_for("data_page"))
    conn = get_db()
    try:
        conn.execute("BEGIN")
        for t in reversed(BACKUP_TABLES):
            conn.execute(f"DELETE FROM {t}")
        for t in BACKUP_TABLES:
            cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({t})")]
            for row in payload.get(t, []):
                keys = [k for k in row if k in cols]
                conn.execute(f"INSERT INTO {t} ({', '.join(keys)}) VALUES ({', '.join('?' * len(keys))})",
                             [row[k] for k in keys])
        conn.commit()
    except (sqlite3.Error, TypeError, AttributeError) as e:
        conn.rollback()
        flash(f"Ошибка восстановления, данные не изменены: {e}", "danger")
        return redirect(url_for("data_page"))
    flash("Данные восстановлены из резервной копии.", "success")
    return redirect(url_for("index"))


# --------------------------------------------------------------------------- import (автовыгрузка)

def import_archive(data, origin, filename=""):
    ok, message, stats = inventory.run_import(get_db(), data, origin, filename)
    if ok and origin != "rerun":
        tmp = LAST_ARCHIVE + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, LAST_ARCHIVE)
    app.logger.warning("inventory import (%s): %s", origin, message)
    return ok, message, stats


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def new_import_token():
    token = secrets.token_urlsafe(32)
    db.set_setting("import_token_hash", token_hash(token))
    return token


@app.route("/api/inventory", methods=["POST"])
def api_inventory():
    """Приём автовыгрузки: POST zip-архива с заголовком «Authorization: Bearer <токен>»."""
    expected = db.get_setting("import_token_hash", "")
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not expected or not token or not secrets.compare_digest(token_hash(token), expected):
        app.logger.warning("inventory api: bad token from %s", client_ip())
        return {"ok": False, "error": "unauthorized"}, 401
    upload = request.files.get("file")
    data = upload.read() if upload else request.get_data()
    if not data:
        return {"ok": False, "error": "пустой запрос: передайте zip в поле file или телом запроса"}, 400
    ok, message, stats = import_archive(data, "api", upload.filename if upload else "")
    return {"ok": ok, "message": message, "stats": stats}, (200 if ok else 422)


@app.route("/import")
@admin_required
def import_page(new_token=None):
    conn = get_db()
    imports = conn.execute("SELECT * FROM imports ORDER BY id DESC LIMIT 30").fetchall()
    unknown = conn.execute("SELECT * FROM import_unknown ORDER BY name COLLATE NOCASE").fetchall()
    aliases = conn.execute(
        """SELECT a.*, s.name AS sw_name FROM sw_aliases a LEFT JOIN software s ON s.id = a.software_id
           ORDER BY a.sample_name COLLATE NOCASE""").fetchall()
    return render_template("import.html", imports=imports, unknown=unknown, aliases=aliases,
                           sw_names=software_names(), has_token=bool(db.get_setting("import_token_hash")),
                           has_last=os.path.exists(LAST_ARCHIVE), new_token=new_token)


@app.route("/import/upload", methods=["POST"])
@admin_required
def import_upload():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Выберите zip-архив выгрузки.", "danger")
        return redirect(url_for("import_page"))
    ok, message, _ = import_archive(upload.read(), "upload", upload.filename)
    flash(("Импорт выполнен. " if ok else "Импорт не выполнен. ") + message, "success" if ok else "danger")
    return redirect(url_for("import_page"))


def rerun_last_import():
    if not os.path.exists(LAST_ARCHIVE):
        return None
    with open(LAST_ARCHIVE, "rb") as f:
        data = f.read()
    return import_archive(data, "rerun", "inventory_last.zip")


@app.route("/import/rerun", methods=["POST"])
@admin_required
def import_rerun():
    result = rerun_last_import()
    if result is None:
        flash("Ещё не было ни одного успешного импорта.", "warning")
    else:
        ok, message, _ = result
        flash(("Импорт выполнен. " if ok else "Импорт не выполнен. ") + message, "success" if ok else "danger")
    return redirect(url_for("import_page"))


@app.route("/import/alias", methods=["POST"])
@admin_required
def import_alias():
    """Решение по нераспознанному названию: сопоставить с программой справочника или игнорировать."""
    conn = get_db()
    key = request.form.get("raw_key", "")
    row = conn.execute("SELECT * FROM import_unknown WHERE raw_key = ?", (key,)).fetchone()
    if not row:
        flash("Это название уже обработано.", "info")
        return redirect(url_for("import_page"))
    if request.form.get("action") == "ignore":
        sw_id, label = None, "будет игнорироваться"
    else:
        name = form_str("software")
        if not name:
            flash("Укажите программу из справочника (или новое название).", "danger")
            return redirect(url_for("import_page"))
        sw_id, created = find_or_create_software(name)
        if created:
            vendor, category, license_type = inventory.CATALOG.get(name, (row["publisher"], "other", "free"))
            conn.execute("UPDATE software SET vendor = ?, category = ?, license_type = ? WHERE id = ?",
                         (vendor, category, license_type, sw_id))
        label = f"→ «{name}»" + (" (новая программа в справочнике — проверьте категорию)" if created else "")
    conn.execute("INSERT OR REPLACE INTO sw_aliases (raw_key, sample_name, software_id) VALUES (?, ?, ?)",
                 (key, row["name"], sw_id))
    conn.execute("DELETE FROM import_unknown WHERE raw_key = ?", (key,))
    conn.commit()
    flash(f"«{row['name']}» {label}.", "success")
    if sw_id is not None:
        result = rerun_last_import()
        if result and result[0]:
            flash("Последняя выгрузка применена заново с учётом сопоставления.", "info")
    return redirect(url_for("import_page") + "#unknown")


@app.route("/import/alias/delete", methods=["POST"])
@admin_required
def import_alias_delete():
    get_db().execute("DELETE FROM sw_aliases WHERE raw_key = ?", (request.form.get("raw_key", ""),))
    get_db().commit()
    flash("Сопоставление удалено. Название снова появится среди нераспознанных после следующего импорта.", "info")
    return redirect(url_for("import_page") + "#aliases")


@app.route("/import/token", methods=["POST"])
@admin_required
def import_token():
    # Токен показывается один раз прямо в ответе, нигде не сохраняется в открытом виде.
    return import_page(new_token=new_import_token())


@app.cli.command("import-inventory")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
def import_inventory_command(path):
    """Импортировать архив автовыгрузки (inventory_latest.zip)."""
    with open(path, "rb") as f:
        ok, message, _ = import_archive(f.read(), "cli", os.path.basename(path))
    click.echo(("OK: " if ok else "ОШИБКА: ") + message)
    if not ok:
        raise SystemExit(1)


@app.cli.command("set-import-token")
def set_import_token_command():
    """Создать токен для отправки автовыгрузки через API (старый перестаёт действовать)."""
    click.echo(new_import_token())


# --------------------------------------------------------------------------- заявки

TICKET_BODY_MAX = 5000
PHOTO_MAX_FILES = 3                 # фото в одном сообщении
PHOTO_MAX_BYTES = 10 * 1024 * 1024  # один исходный файл
PHOTO_SIDE = 1600                   # фото уменьшается до этой стороны (по большей)
THUMB_SIDE = 320                    # миниатюра в переписке
MAX_TICKET_PCS = 100  # компьютеров в одной заявке


def now_str():
    return time.strftime("%Y-%m-%d %H:%M")


# Общая часть запросов к заявкам: текущее имя ПК (или список ПК), число «следящих»
# и признаки для текущего пользователя.
TICKETS_SQL = """
SELECT t.*, a.num AS aud_num, c.num AS pc_num, ta.num AS t_aud_num,
       COALESCE(c.auditorium_id, t.auditorium_id) AS aud_id,
       (SELECT group_concat(CASE WHEN tc_c.id IS NULL THEN tc.hostname
                                 ELSE printf('PC-%02d-%02d', tc_a.num, tc_c.num) END, ' ')
          FROM ticket_computers tc
          LEFT JOIN computers tc_c ON tc_c.id = tc.computer_id
          LEFT JOIN auditoriums tc_a ON tc_a.id = tc_c.auditorium_id
         WHERE tc.ticket_id = t.id) AS pc_list,
       (SELECT group_concat(tc.computer_id, ' ') FROM ticket_computers tc
         WHERE tc.ticket_id = t.id AND tc.computer_id IS NOT NULL) AS pc_ids,
       (SELECT COUNT(*) FROM ticket_messages m WHERE m.ticket_id = t.id) AS msg_count,
       (SELECT COUNT(*) FROM ticket_watchers w WHERE w.ticket_id = t.id) AS watchers,
       me.user_id IS NOT NULL AS watching, COALESCE(me.unread, 0) AS my_unread,
       (SELECT av.version FROM user_avatars av WHERE av.user_id = t.author_id) AS author_avatar
FROM tickets t
LEFT JOIN computers c ON c.id = t.computer_id
LEFT JOIN auditoriums a ON a.id = c.auditorium_id
LEFT JOIN auditoriums ta ON ta.id = t.auditorium_id
LEFT JOIN ticket_watchers me ON me.ticket_id = t.id AND me.user_id = ?
"""


def get_ticket_or_404(ticket_id):
    """Заявка с текущим именем ПК. Заявки видны всем вошедшим — чтобы не создавать дубли."""
    row = get_db().execute(TICKETS_SQL + " WHERE t.id = ?", (current_user()["id"], ticket_id)).fetchone()
    if not row:
        abort(404)
    return ticket_dict(row)


def ticket_dict(row):
    t = dict(row)
    # Если ПК переименовали (перенесли) — показываем актуальное имя, если удалили — сохранённое.
    t["pc_link"] = pc_hostname(t["aud_num"], t["pc_num"]) if t["pc_num"] else None
    t["aud_link"] = aud_code(t["t_aud_num"]) if t["t_aud_num"] else None
    # Заявка на несколько ПК: их имена (по порядку) и id тех, что ещё не удалены.
    t["pcs"] = sorted((t["pc_list"] or "").split())
    t["pc_id_set"] = {int(x) for x in (t["pc_ids"] or "").split()}
    if t["pcs"]:
        t["pc_label"] = ", ".join(t["pcs"]) if len(t["pcs"]) <= 3 else \
            f"{t['aud_link'] or t['hostname']}: {len(t['pcs'])} ПК"
    else:
        t["pc_label"] = t["pc_link"] or t["aud_link"] or t["hostname"]
    t["is_open"] = t["status"] in TICKET_OPEN
    user = current_user()
    t["is_author"] = bool(user and t["author_id"] is not None and t["author_id"] == user["id"])
    t["unread"] = t["admin_unread"] if user and user["admin"] else t["my_unread"]
    # Срок для заявки на установку: «горит», если открыта и нужна сегодня или завтра (или срок прошёл).
    t["need_by_days"] = (date.fromisoformat(t["need_by"]) - date.today()).days if t["need_by"] else None
    t["urgent"] = t["is_open"] and t["need_by_days"] is not None and t["need_by_days"] <= 1
    return t


def need_by_text(t):
    """Срок заявки словами: «к 05.11 (завтра)»."""
    days = t["need_by_days"]
    when = {0: "сегодня", 1: "завтра", 2: "послезавтра"}.get(days) or ("срок прошёл" if days < 0 else "")
    return f"к {date.fromisoformat(t['need_by']).strftime('%d.%m')}" + (f" ({when})" if when else "")


app.jinja_env.globals["need_by_text"] = need_by_text


def make_photo(data):
    """Байты фото -> (JPEG до PHOTO_SIDE px, миниатюра до THUMB_SIDE px). ValueError — если это не картинка."""
    img = load_image(data)
    big, small = img.copy(), img.copy()
    big.thumbnail((PHOTO_SIDE, PHOTO_SIDE))
    small.thumbnail((THUMB_SIDE, THUMB_SIDE))
    return to_jpeg(big, 85), to_jpeg(small, 80)


def read_photos():
    """Фото из поля photos формы -> (список (фото, миниатюра), предупреждение или None).
    Если с фото что-то не так, текст сообщения всё равно сохраняется — без фото, с предупреждением."""
    files = [f for f in request.files.getlist("photos") if f and f.filename]
    if not files:
        return [], None
    if not pillow_available():
        app.logger.error("ticket photos: Pillow is not installed, run pip install -r requirements.txt")
        return [], "Фото не приложены: на сервере не установлена библиотека Pillow. Сообщите администратору."
    if len(files) > PHOTO_MAX_FILES:
        return [], f"Фото не приложены: можно не больше {PHOTO_MAX_FILES} в одном сообщении."
    photos = []
    for f in files:
        data = f.read(PHOTO_MAX_BYTES + 1)
        if len(data) > PHOTO_MAX_BYTES:
            return [], f"Фото не приложены: «{f.filename}» больше {PHOTO_MAX_BYTES // 1024 // 1024} МБ."
        try:
            photos.append(make_photo(data))
        except ValueError as e:
            app.logger.warning("ticket photo rejected: %s: %s", f.filename, e)
            return [], f"Фото не приложены: «{f.filename}» не похож на картинку. Подойдут JPG, PNG, WEBP или GIF."
    return photos, None


def save_photos(conn, ticket_id, message_id, photos, stamp):
    conn.executemany("INSERT INTO ticket_attachments (ticket_id, message_id, image, thumb, created_at) "
                     "VALUES (?, ?, ?, ?, ?)", [(ticket_id, message_id, big, small, stamp) for big, small in photos])


def add_message(conn, ticket_id, user, body, stamp, status=""):
    return conn.execute(
        "INSERT INTO ticket_messages (ticket_id, author_id, author_name, is_admin, body, status, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ticket_id, user["id"], user["name"], int(user["admin"]), body, status, stamp)).lastrowid


@app.route("/tickets/photo/<int:photo_id>")
def ticket_photo(photo_id):
    column = "thumb" if request.args.get("thumb") else "image"
    row = get_db().execute(f"SELECT {column} FROM ticket_attachments WHERE id = ?", (photo_id,)).fetchone()
    if not row:
        abort(404)
    resp = Response(row[0], mimetype="image/jpeg")
    resp.headers["Cache-Control"] = "private, max-age=2592000, immutable"  # фото по id не меняется
    return resp


def mark_watchers_unread(conn, ticket_id, except_user=None):
    conn.execute("UPDATE ticket_watchers SET unread = 1 WHERE ticket_id = ? AND user_id IS NOT ?",
                 (ticket_id, except_user))


def watch(conn, ticket_id, user_id):
    conn.execute("INSERT OR IGNORE INTO ticket_watchers (ticket_id, user_id) VALUES (?, ?)", (ticket_id, user_id))


def ticket_url(ticket_id):
    return site_url_for("ticket", ticket_id=ticket_id)


def notify_admin(text):
    token, chat = db.get_setting("telegram_token", ""), db.get_setting("telegram_chat", "")
    if token and chat:
        telegram.send_async(token, chat, text)


def tg_ticket_text(icon, t, who, body, photos=0):
    from html import escape
    lines = [f"{icon} <b>Заявка №{t['id']}: {escape(t['title'])}</b>",
             " · ".join(escape(x) for x in [TICKET_KINDS.get(t["kind"], ""), t["pc_label"] or "",
                                            need_by_text(t) if t["need_by"] else "", who] if x)]
    if photos:
        lines.append(f"📎 фото: {photos}")
    if body:
        lines += ["", escape(body if len(body) <= 700 else body[:700] + "…")]
    lines += ["", ticket_url(t["id"])]
    return "\n".join(lines)


def similar_tickets(computer_ids=(), software="", title="", exclude=None, limit=5, auditorium_id=None):
    """Открытые заявки, похожие на новую: те же ПК или аудитория, та же программа, общие слова в теме."""
    def stems(text):
        return {w[:5] for w in "".join(ch if ch.isalnum() else " " for ch in text.lower()).split() if len(w) >= 4}
    conn = get_db()
    computer_ids = set(computer_ids)
    aud_id = auditorium_id
    if computer_ids:
        row = conn.execute("SELECT auditorium_id FROM computers WHERE id = ?", (min(computer_ids),)).fetchone()
        aud_id = row and row[0]
    rows = conn.execute(TICKETS_SQL + " WHERE t.status IN (%s)" % ",".join("?" * len(TICKET_OPEN)),
                        (current_user()["id"], *TICKET_OPEN)).fetchall()
    software, words = software.strip().lower(), stems(title + " " + software)
    scored = []
    for r in rows:
        if r["id"] == exclude:
            continue
        score = 0
        r_pcs = {int(x) for x in (r["pc_ids"] or "").split()} | ({r["computer_id"]} if r["computer_id"] else set())
        if computer_ids & r_pcs:
            score += 3  # общие компьютеры
        elif not computer_ids and aud_id and not r["computer_id"] and not r["pc_list"] \
                and r["auditorium_id"] == aud_id:
            score += 3  # обе заявки — на всю аудиторию
        elif aud_id and r["aud_id"] == aud_id:
            score += 1
        if software and (software == r["software_name"].lower() or software in r["title"].lower()):
            score += 3
        score += len(words & stems(r["title"] + " " + r["software_name"]))
        if score >= 2:
            scored.append((score, r["id"], ticket_dict(r)))
    scored.sort(key=lambda x: (-x[0], -x[1]))
    return [t for _, _, t in scored[:limit]]


def find_computer(hostname):
    parsed = parse_hostname(hostname) if hostname else None
    return parsed and get_db().execute(
        "SELECT c.id, c.auditorium_id FROM computers c JOIN auditoriums a ON a.id = c.auditorium_id "
        "WHERE a.num = ? AND c.num = ?", parsed).fetchone()


def find_auditorium(code):
    num = parse_aud_code(code) if code else None
    return num and get_db().execute("SELECT * FROM auditoriums WHERE num = ?", (num,)).fetchone()


def install_targets(t):
    """Компьютеры, на которые ставится программа по заявке: один ПК, выбранные ПК или все рабочие ПК аудитории."""
    if t["computer_id"]:
        return [t["computer_id"]]
    if t["pcs"]:
        return sorted(t["pc_id_set"])
    if t["auditorium_id"]:
        return [r[0] for r in get_db().execute(
            "SELECT id FROM computers WHERE auditorium_id = ? AND status != 'decommissioned' ORDER BY num",
            (t["auditorium_id"],))]
    return []


@app.route("/tickets/similar")
def tickets_similar():
    pcs = [find_computer(h.strip()) for h in request.args.get("pcs", "").split(",")[:MAX_TICKET_PCS]]
    aud = find_auditorium(request.args.get("auditorium", "").strip())
    found = similar_tickets([c["id"] for c in pcs if c], request.args.get("software", "")[:200],
                            request.args.get("title", "")[:200], auditorium_id=aud["id"] if aud else None)
    return {"tickets": [dict(id=t["id"], title=t["title"], status=TICKET_STATUSES[t["status"]],
                             pc=t["pc_label"], watchers=t["watchers"], watching=bool(t["watching"]),
                             url=url_for("ticket", ticket_id=t["id"])) for t in found]}


@app.route("/tickets")
def tickets():
    user = current_user()
    status = request.args.get("status", "open")
    kind = request.args.get("kind", "")
    mine = request.args.get("mine") == "1" and not user["admin"]
    where, params = [], [user["id"]]
    if mine:
        where.append("me.user_id IS NOT NULL")
    if status == "open":
        where.append("t.status IN (%s)" % ",".join("?" * len(TICKET_OPEN)))
        params += TICKET_OPEN
    elif status in TICKET_STATUSES:
        where.append("t.status = ?")
        params.append(status)
    if kind in TICKET_KINDS:
        where.append("t.kind = ?")
        params.append(kind)
    rows = get_db().execute(
        TICKETS_SQL + (" WHERE " + " AND ".join(where) if where else "")
        + " ORDER BY t.status IN ('done', 'rejected'),"
          " CASE WHEN t.status IN ('done', 'rejected') OR t.need_by = '' THEN 1 ELSE 0 END, t.need_by,"
          " t.updated_at DESC, t.id DESC", params).fetchall()
    return render_template("tickets.html", tickets=[ticket_dict(r) for r in rows], status=status, kind=kind,
                           mine=mine)


@app.route("/tickets/new", methods=["GET", "POST"])
def ticket_new():
    user = current_user()
    conn = get_db()
    # ПК отмечаются галочками (pc); со страницы компьютера приходит ?computer=PC-.. — он сразу отмечен.
    pcs = request.values.getlist("pc") or [request.values.get("computer", "")]
    pcs = list(dict.fromkeys(h.strip().upper() for h in pcs if h.strip()))[:MAX_TICKET_PCS]
    auditorium = request.values.get("auditorium", "")
    if not auditorium and pcs and parse_hostname(pcs[0]):
        auditorium = aud_code(parse_hostname(pcs[0])[0])
    form = dict(kind=request.values.get("kind", "problem"), pcs=pcs, auditorium=auditorium,
                software=request.values.get("software", ""), title="", body="", need_by="")
    if request.method == "POST":
        form.update(title=form_str("title"), body=request.form.get("body", "").strip()[:TICKET_BODY_MAX],
                    software=form_str("software"), auditorium=form_str("auditorium", 20),
                    need_by=form_date("need_by") if form["kind"] == "install" else "")
        computers = [find_computer(h) for h in pcs]
        missing = [h for h, c in zip(pcs, computers) if not c]
        aud = find_auditorium(form["auditorium"])
        if not aud and computers and not missing:
            aud = conn.execute("SELECT * FROM auditoriums WHERE id = ?", (computers[0]["auditorium_id"],)).fetchone()
        if form["kind"] not in TICKET_KINDS:
            flash("Выберите тип заявки.", "danger")
        elif missing:
            flash(f"Компьютер {missing[0]} не найден.", "danger")
        elif form["auditorium"] and not aud:
            flash(f"Аудитория {form['auditorium']} не найдена.", "danger")
        elif any(c["auditorium_id"] != aud["id"] for c in computers):
            other = next(h for h, c in zip(pcs, computers) if c["auditorium_id"] != aud["id"])
            flash(f"Компьютер {other} не в аудитории {aud_code(aud['num'])}. "
                  "В одной заявке — компьютеры одной аудитории.", "danger")
        elif form["kind"] == "install" and not form["software"]:
            flash("Укажите, какую программу установить.", "danger")
        elif form["need_by"] is None:
            form["need_by"] = ""
            flash("Неверная дата в поле «Нужно к».", "danger")
        elif form["need_by"] and form["need_by"] < date.today().isoformat():
            flash("Дата в поле «Нужно к» уже прошла.", "danger")
        elif form["kind"] == "problem" and not form["title"]:
            flash("Кратко опишите проблему в поле «Тема».", "danger")
        else:
            if not form["title"]:
                form["title"] = f"Установить {form['software']}"
            stamp = now_str()
            # Один ПК — computer_id; несколько — аудитория + ticket_computers; ни одного — вся аудитория.
            single = computers[0] if len(computers) == 1 else None
            cur = conn.execute(
                """INSERT INTO tickets (kind, title, computer_id, auditorium_id, hostname, software_name, need_by,
                                        author_id, author_username, author_name, created_at, updated_at, admin_unread)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (form["kind"], form["title"], single["id"] if single else None,
                 aud["id"] if aud and not single else None,
                 pcs[0] if single else aud_code(aud["num"]) if aud else "",
                 form["software"] if form["kind"] == "install" else "", form["need_by"],
                 user["id"], user["username"], user["name"], stamp, stamp, 0 if user["admin"] else 1))
            if len(computers) > 1:
                conn.executemany("INSERT INTO ticket_computers (ticket_id, computer_id, hostname) VALUES (?, ?, ?)",
                                 [(cur.lastrowid, c["id"], h) for h, c in zip(pcs, computers)])
            photos, photo_warning = read_photos()
            if form["body"] or photos:
                msg_id = add_message(conn, cur.lastrowid, user, form["body"], stamp)
                save_photos(conn, cur.lastrowid, msg_id, photos, stamp)
            if not user["admin"]:
                watch(conn, cur.lastrowid, user["id"])
            conn.commit()
            app.logger.warning("ticket #%s created by %s", cur.lastrowid, user["username"])
            if not user["admin"]:
                notify_admin(tg_ticket_text("🆕", get_ticket_or_404(cur.lastrowid), user["name"], form["body"],
                                            len(photos)))
            flash(f"Заявка №{cur.lastrowid} отправлена. Ответ появится здесь, на странице заявки.", "success")
            if photo_warning:
                flash(photo_warning, "warning")
            return redirect(url_for("ticket", ticket_id=cur.lastrowid))
    return render_template("ticket_form.html", form=form, computers=list_computers(),
                           auditoriums=list_auditoriums(), sw_names=software_names())


@app.route("/tickets/<int:ticket_id>")
def ticket(ticket_id):
    t = get_ticket_or_404(ticket_id)
    conn = get_db()
    # Отмечаем прочитанным для того, кто смотрит.
    if current_user()["admin"] and t["admin_unread"]:
        conn.execute("UPDATE tickets SET admin_unread = 0 WHERE id = ?", (ticket_id,))
        conn.commit()
    elif t["my_unread"]:
        conn.execute("UPDATE ticket_watchers SET unread = 0 WHERE ticket_id = ? AND user_id = ?",
                     (ticket_id, current_user()["id"]))
        conn.commit()
    # Автор сообщения — по профилю: актуальное имя и аватарка (у старых сообщений без автора — имя как было).
    messages = conn.execute(
        """SELECT m.*, COALESCE(NULLIF(u.full_name, ''), u.username) AS author_now, av.version AS avatar
           FROM ticket_messages m
           LEFT JOIN users u ON u.id = m.author_id
           LEFT JOIN user_avatars av ON av.user_id = m.author_id
           WHERE m.ticket_id = ? ORDER BY m.id""", (ticket_id,)).fetchall()
    photos = {}
    for r in conn.execute("SELECT id, message_id FROM ticket_attachments WHERE ticket_id = ? ORDER BY id",
                          (ticket_id,)):
        photos.setdefault(r["message_id"], []).append(r["id"])
    # Для заявки на установку: на скольких ПК программы ещё нет.
    targets = install_targets(t) if t["kind"] == "install" and t["software_name"] else []
    missing = 0
    if targets:
        have = conn.execute(
            """SELECT COUNT(*) FROM installations i JOIN software s ON s.id = i.software_id
               WHERE s.name = ? AND i.computer_id IN (%s)""" % ",".join("?" * len(targets)),
            (t["software_name"], *targets)).fetchone()[0]
        missing = len(targets) - have
    similar = similar_tickets(install_targets(t) if t["computer_id"] or t["pcs"] else (), t["software_name"],
                              t["title"], exclude=t["id"], limit=3,
                              auditorium_id=t["auditorium_id"]) if t["is_open"] else []
    # Список ПК заявки: ссылки только на существующие компьютеры.
    pc_rows = [dict(hostname=h, exists=bool(find_computer(h))) for h in t["pcs"]]
    # Кого касается заявка: автор первым, потом остальные по имени.
    watchers = conn.execute(
        USERS_SQL + """ JOIN ticket_watchers w ON w.user_id = u.id AND w.ticket_id = ?
           ORDER BY u.id IS NOT ? , COALESCE(NULLIF(u.full_name, ''), u.username) COLLATE NOCASE""",
        (ticket_id, t["author_id"])).fetchall()
    # Администратор может добавить в заявку тех, кого она касается, но кто ещё не отметился.
    candidates = conn.execute(
        """SELECT id, username, full_name FROM users
           WHERE id NOT IN (SELECT user_id FROM ticket_watchers WHERE ticket_id = ?)
           ORDER BY COALESCE(NULLIF(full_name, ''), username) COLLATE NOCASE""",
        (ticket_id,)).fetchall() if current_user()["admin"] else []
    return render_template("ticket.html", t=t, messages=messages, photos=photos, similar=similar, pc_rows=pc_rows,
                           watchers=watchers, candidates=candidates, photo_max=PHOTO_MAX_FILES,
                           install_total=len(targets), install_missing=missing,
                           can_write=t["is_open"] or current_user()["admin"] or bool(t["watching"]))


@app.route("/tickets/<int:ticket_id>/reply", methods=["POST"])
def ticket_reply(ticket_id):
    t = get_ticket_or_404(ticket_id)
    user = current_user()
    body = request.form.get("body", "").strip()[:TICKET_BODY_MAX]
    status = request.form.get("status", "") if user["admin"] else ""
    if status not in TICKET_STATUSES or status == t["status"]:
        status = ""
    if not user["admin"] and not t["is_open"] and not t["watching"]:
        # В закрытой заявке пишут только автор и следящие — и тогда она открывается снова.
        flash("Заявка закрыта. Если проблема повторилась — создайте новую.", "warning")
        return redirect(url_for("ticket", ticket_id=ticket_id))
    photos, photo_warning = read_photos()
    if photo_warning:
        flash(photo_warning, "warning")
    if not user["admin"] and not t["is_open"] and (body or photos):
        status = "new"
    if not body and not status and not photos:
        if not photo_warning:
            flash("Напишите сообщение" + (" или выберите новый статус." if user["admin"] else "."), "warning")
        return redirect(url_for("ticket", ticket_id=ticket_id))
    conn = get_db()
    stamp = now_str()
    msg_id = add_message(conn, ticket_id, user, body, stamp, status)
    save_photos(conn, ticket_id, msg_id, photos, stamp)
    conn.execute("UPDATE tickets SET updated_at = ?, status = COALESCE(NULLIF(?, ''), status) WHERE id = ?",
                 (stamp, status, ticket_id))
    if not user["admin"]:
        watch(conn, ticket_id, user["id"])  # написавший в заявке получает ответы по ней
        conn.execute("UPDATE tickets SET admin_unread = 1 WHERE id = ?", (ticket_id,))
    mark_watchers_unread(conn, ticket_id, except_user=user["id"])
    conn.commit()
    if not user["admin"]:
        notify_admin(tg_ticket_text("🔄" if status == "new" else "💬", t, user["name"], body, len(photos)))
    flash("Сообщение отправлено." if body or photos else "Статус изменён.", "success")
    return redirect(url_for("ticket", ticket_id=ticket_id) + "#last")


@app.route("/tickets/<int:ticket_id>/install", methods=["POST"])
@admin_required
def ticket_install(ticket_id):
    """Заявка на установку: отметить программу на ПК и закрыть заявку одним действием."""
    t = get_ticket_or_404(ticket_id)
    targets = install_targets(t) if t["kind"] == "install" and t["software_name"] else []
    if not targets:
        abort(400, "В заявке не указан компьютер (или в аудитории нет компьютеров) или программа.")
    conn = get_db()
    sw_id, created = find_or_create_software(t["software_name"])
    version, today = form_str("version", 50), date.today().isoformat()
    conn.executemany("INSERT OR IGNORE INTO installations (computer_id, software_id, version, installed_at) "
                     "VALUES (?, ?, ?, ?)", [(pc_id, sw_id, version, today) for pc_id in targets])
    where = t["pc_label"] if t["computer_id"] or 1 < len(t["pcs"]) <= 3 else f"{t['pc_label']} ({len(targets)} ПК)"
    stamp = now_str()
    conn.execute("INSERT INTO ticket_messages (ticket_id, author_name, is_admin, body, status, created_at) "
                 "VALUES (?, ?, 1, ?, 'done', ?)",
                 (ticket_id, current_user()["name"], f"Программа {t['software_name']} установлена на {where}.",
                  stamp))
    conn.execute("UPDATE tickets SET status = 'done', updated_at = ? WHERE id = ?", (stamp, ticket_id))
    mark_watchers_unread(conn, ticket_id)
    conn.commit()
    flash(f"{t['software_name']} отмечена на {where}, заявка выполнена."
          + (" Программа добавлена в справочник — проверьте категорию и лицензию." if created else ""), "success")
    return redirect(url_for("ticket", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/watch", methods=["POST"])
def ticket_watch(ticket_id):
    """«Меня тоже касается» — вместо дубля: пользователь будет получать ответы по заявке."""
    t = get_ticket_or_404(ticket_id)
    user = current_user()
    if user["admin"] or t["is_author"]:
        return redirect(url_for("ticket", ticket_id=ticket_id))
    conn = get_db()
    if t["watching"]:
        conn.execute("DELETE FROM ticket_watchers WHERE ticket_id = ? AND user_id = ?", (ticket_id, user["id"]))
        flash("Вы больше не следите за этой заявкой.", "info")
    else:
        watch(conn, ticket_id, user["id"])
        flash("Отмечено: вас это тоже касается. Ответы по заявке будут приходить и вам.", "success")
    conn.commit()
    return redirect(url_for("ticket", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/watchers", methods=["POST"])
@admin_required
def ticket_watchers(ticket_id):
    """Администратор добавляет в заявку пользователя, которого она касается, или убирает его."""
    t = get_ticket_or_404(ticket_id)
    conn = get_db()
    try:
        user_id = int(request.form.get("user_id", ""))
    except ValueError:
        user_id = None
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone() if user_id else None
    if not row:
        flash("Выберите пользователя.", "warning")
        return redirect(url_for("ticket", ticket_id=ticket_id))
    name = row["full_name"] or row["username"]
    if request.form.get("action") == "remove":
        if row["id"] == t["author_id"]:
            flash("Автора заявки убрать нельзя.", "warning")
        else:
            conn.execute("DELETE FROM ticket_watchers WHERE ticket_id = ? AND user_id = ?", (ticket_id, row["id"]))
            flash(f"{name} больше не в заявке.", "info")
    else:
        watch(conn, ticket_id, row["id"])
        # Заявка появится у пользователя как непрочитанная — так он узнает, что его добавили.
        conn.execute("UPDATE ticket_watchers SET unread = 1 WHERE ticket_id = ? AND user_id = ?", (ticket_id, row["id"]))
        flash(f"{name} добавлен(а) в заявку: ответы по ней будут приходить и ему(ей).", "success")
    conn.commit()
    return redirect(url_for("ticket", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
@admin_required
def ticket_delete(ticket_id):
    get_ticket_or_404(ticket_id)
    get_db().execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
    get_db().commit()
    flash(f"Заявка №{ticket_id} удалена.", "info")
    return redirect(url_for("tickets"))


# --------------------------------------------------------------------------- Telegram

@app.route("/settings/telegram", methods=["POST"])
@admin_required
def telegram_settings():
    action = request.form.get("action", "save")
    token = form_str("token", 100) or db.get_setting("telegram_token", "")
    if action == "save":
        if request.form.get("clear"):
            for key in ("telegram_token", "telegram_chat"):
                db.set_setting(key, "")
            flash("Уведомления в Telegram отключены.", "info")
        else:
            db.set_setting("telegram_token", token)
            db.set_setting("telegram_chat", form_str("chat", 50))
            db.set_setting("site_url", form_str("site_url").rstrip("/"))
            flash("Настройки Telegram сохранены.", "success")
        return redirect(url_for("data_page") + "#telegram")
    if not token:
        flash("Сначала укажите токен бота.", "danger")
        return redirect(url_for("data_page") + "#telegram")
    try:
        if action == "chats":
            chats = telegram.recent_chats(token)
            if not chats:
                flash("Боту пока никто не писал. Напишите боту любое сообщение (или добавьте его в группу) "
                      "и нажмите кнопку ещё раз.", "warning")
            for chat_id, title in chats:
                flash(f"chat id {chat_id} — {title}", "info")
        else:
            chat = form_str("chat", 50) or db.get_setting("telegram_chat", "")
            telegram.send(token, chat, f"✅ {SITE_NAME}: уведомления о заявках будут приходить сюда.")
            flash("Тестовое сообщение отправлено — проверьте Telegram.", "success")
    except RuntimeError as e:
        flash(f"Telegram ответил ошибкой: {e}", "danger")
    return redirect(url_for("data_page") + "#telegram")


@app.route("/robots.txt")
def robots():
    # Реестр — внутренний документ, поисковикам его индексировать незачем.
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="Страница не найдена."), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=e.description), 400


if __name__ == "__main__":
    app.run(debug=True)
