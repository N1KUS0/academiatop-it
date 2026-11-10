"""Работа с базой SQLite: схема, подключение, справочники."""
import re
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS auditoriums (
    id    INTEGER PRIMARY KEY,
    num   INTEGER NOT NULL UNIQUE CHECK (num > 0),
    floor INTEGER,
    note  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS computers (
    id            INTEGER PRIMARY KEY,
    auditorium_id INTEGER NOT NULL REFERENCES auditoriums(id) ON DELETE RESTRICT,
    num           INTEGER NOT NULL CHECK (num > 0),
    inv_number    TEXT NOT NULL DEFAULT '',
    os            TEXT NOT NULL DEFAULT '',
    os_version    TEXT NOT NULL DEFAULT '',
    cpu           TEXT NOT NULL DEFAULT '',
    ram           TEXT NOT NULL DEFAULT '',
    disk          TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active',
    note          TEXT NOT NULL DEFAULT '',
    inv_hw_at     TEXT NOT NULL DEFAULT '',     -- когда ПК последний раз прислал «железо» (время сбора на ПК)
    inv_sw_at     TEXT NOT NULL DEFAULT '',     -- когда ПК последний раз прислал список программ
    UNIQUE (auditorium_id, num)
);

CREATE TABLE IF NOT EXISTS software (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    vendor       TEXT NOT NULL DEFAULT '',
    category     TEXT NOT NULL DEFAULT 'other',
    license_type TEXT NOT NULL DEFAULT 'free',
    url          TEXT NOT NULL DEFAULT '',
    note         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS installations (
    id           INTEGER PRIMARY KEY,
    computer_id  INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
    software_id  INTEGER NOT NULL REFERENCES software(id) ON DELETE CASCADE,
    version      TEXT NOT NULL DEFAULT '',
    installed_at TEXT NOT NULL DEFAULT '',
    note         TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT 'manual',   -- 'manual' — внесено вручную, 'auto' — из автовыгрузки
    UNIQUE (computer_id, software_id)
);

-- История изменений на ПК (см. history.py): установка и удаление программ, смена версий, «железа», имени ПК.
CREATE TABLE IF NOT EXISTS pc_history (
    id          INTEGER PRIMARY KEY,
    computer_id INTEGER REFERENCES computers(id) ON DELETE SET NULL,
    hostname    TEXT NOT NULL,                  -- имя ПК на момент события (если ПК удалят или переименуют)
    at          TEXT NOT NULL,                  -- когда записано: ГГГГ-ММ-ДД ЧЧ:ММ
    kind        TEXT NOT NULL,                  -- вид события, см. history.py
    field       TEXT NOT NULL DEFAULT '',       -- программа или поле «железа»
    old         TEXT NOT NULL DEFAULT '',
    new         TEXT NOT NULL DEFAULT '',
    date        TEXT NOT NULL DEFAULT '',       -- дата установки программы по данным Windows, если известна
    software_id INTEGER REFERENCES software(id) ON DELETE SET NULL,
    source      TEXT NOT NULL DEFAULT 'manual', -- auto — автовыгрузка, manual — вручную, ticket:N — по заявке
    who         TEXT NOT NULL DEFAULT ''        -- кто внёс вручную
);
CREATE INDEX IF NOT EXISTS pc_history_pc ON pc_history (computer_id, id);
CREATE INDEX IF NOT EXISTS pc_history_at ON pc_history (at);

-- «Включить» (Wake-on-LAN): ответил ли ПК на ping за несколько минут. Задания старше суток удаляются.
CREATE TABLE IF NOT EXISTS wake_jobs (
    id          INTEGER PRIMARY KEY,
    computer_id INTEGER REFERENCES computers(id) ON DELETE CASCADE,
    hostname    TEXT NOT NULL,
    started_at  REAL NOT NULL,
    finished_at REAL,
    state       TEXT NOT NULL DEFAULT 'waiting',  -- waiting / up / failed / already (уже был в сети) / lost (проверка прервалась)
    who         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS wake_jobs_started ON wake_jobs (started_at);

-- Журнал импортов автовыгрузки
CREATE TABLE IF NOT EXISTS imports (
    id         INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    origin     TEXT NOT NULL DEFAULT '',   -- api / upload / cli
    filename   TEXT NOT NULL DEFAULT '',
    ok         INTEGER NOT NULL DEFAULT 1,
    message    TEXT NOT NULL DEFAULT '',
    stats      TEXT NOT NULL DEFAULT '{}'
);

-- Названия из автовыгрузки, не подошедшие ни под одно правило (по последнему импорту)
CREATE TABLE IF NOT EXISTS import_unknown (
    raw_key   TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    publisher TEXT NOT NULL DEFAULT '',
    versions  TEXT NOT NULL DEFAULT '',
    hosts     TEXT NOT NULL DEFAULT ''
);

-- Решения администратора по нераспознанным названиям: software_id NULL — игнорировать
CREATE TABLE IF NOT EXISTS sw_aliases (
    raw_key     TEXT PRIMARY KEY,
    sample_name TEXT NOT NULL DEFAULT '',
    software_id INTEGER REFERENCES software(id) ON DELETE CASCADE
);

-- Пользователи с правом просмотра. Администратор хранится отдельно, в settings.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name     TEXT NOT NULL DEFAULT '',   -- отображаемое имя (ФИО); пусто — показывается логин
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,  -- пароль выдал администратор: при входе задать свой
    reset_requested_at   TEXT NOT NULL DEFAULT '',    -- когда нажал «Забыли пароль?» (пусто — не просил)
    created_at    TEXT NOT NULL DEFAULT '',
    last_login    TEXT NOT NULL DEFAULT ''
);

-- Аватарки пользователей: квадратный JPEG, уже уменьшенный при загрузке.
CREATE TABLE IF NOT EXISTS user_avatars (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    image      BLOB NOT NULL,
    version    TEXT NOT NULL                   -- случайная метка в ссылке: новая картинка — новый адрес, кэш браузера не мешает
);

-- Заявки пользователей: проблема или запрос на установку ПО.
CREATE TABLE IF NOT EXISTS tickets (
    id              INTEGER PRIMARY KEY,
    kind            TEXT NOT NULL DEFAULT 'problem',   -- problem / install
    status          TEXT NOT NULL DEFAULT 'new',       -- см. TICKET_STATUSES
    title           TEXT NOT NULL,
    computer_id     INTEGER REFERENCES computers(id) ON DELETE SET NULL,
    auditorium_id   INTEGER REFERENCES auditoriums(id) ON DELETE SET NULL,  -- заявка на всю аудиторию, без ПК
    hostname        TEXT NOT NULL DEFAULT '',          -- имя ПК или аудитории на момент создания (если удалят)
    software_name   TEXT NOT NULL DEFAULT '',
    need_by         TEXT NOT NULL DEFAULT '',          -- установка: к какой дате нужно (ISO), пусто — не важно
    edited_at       TEXT NOT NULL DEFAULT '',          -- когда заявку меняли (тему, место, программу, срок)
    edited_by       TEXT NOT NULL DEFAULT '',          -- кто менял последним
    author_id       INTEGER,                           -- users.id; NULL — администратор или удалённый пользователь
    author_username TEXT NOT NULL DEFAULT '',
    author_name     TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    admin_unread    INTEGER NOT NULL DEFAULT 1,        -- есть новое для администратора
    user_unread     INTEGER NOT NULL DEFAULT 0         -- есть новое для автора
);
CREATE INDEX IF NOT EXISTS tickets_author ON tickets (author_id);

-- Заявка на несколько ПК одной аудитории (tickets.auditorium_id — их аудитория).
-- На один ПК — tickets.computer_id, на всю аудиторию — только tickets.auditorium_id.
CREATE TABLE IF NOT EXISTS ticket_computers (
    ticket_id   INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    computer_id INTEGER REFERENCES computers(id) ON DELETE SET NULL,
    hostname    TEXT NOT NULL DEFAULT '',      -- имя ПК на момент создания (если ПК удалят)
    PRIMARY KEY (ticket_id, hostname)
);
CREATE INDEX IF NOT EXISTS ticket_computers_pc ON ticket_computers (computer_id);

CREATE TABLE IF NOT EXISTS ticket_messages (
    id          INTEGER PRIMARY KEY,
    ticket_id   INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_id   INTEGER,                    -- users.id; NULL — администратор или неизвестно
    author_name TEXT NOT NULL DEFAULT '',
    is_admin    INTEGER NOT NULL DEFAULT 0,
    body        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',   -- новый статус, если сообщение его меняло
    created_at  TEXT NOT NULL,
    edited_at   TEXT NOT NULL DEFAULT '',   -- когда автор менял текст или фото
    system      INTEGER NOT NULL DEFAULT 0  -- 1 — служебная строка «изменения в заявке», её не редактируют
);
CREATE INDEX IF NOT EXISTS ticket_messages_ticket ON ticket_messages (ticket_id);

-- Фото к сообщениям заявки: уменьшенный JPEG и миниатюра, без метаданных.
CREATE TABLE IF NOT EXISTS ticket_attachments (
    id         INTEGER PRIMARY KEY,
    ticket_id  INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    message_id INTEGER REFERENCES ticket_messages(id) ON DELETE CASCADE,
    image      BLOB NOT NULL,
    thumb      BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ticket_attachments_msg ON ticket_attachments (message_id);

-- Кто следит за заявкой: автор и те, кого она «тоже касается». unread — есть новое для этого пользователя.
CREATE TABLE IF NOT EXISTS ticket_watchers (
    ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL,
    unread    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ticket_id, user_id)
);
CREATE INDEX IF NOT EXISTS ticket_watchers_user ON ticket_watchers (user_id);

-- Нажатия «Забыли пароль?» — чтобы с одного адреса не засыпать администратора уведомлениями.
CREATE TABLE IF NOT EXISTS forgot_requests (
    ip TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS login_failures (
    ip TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS login_failures_ip ON login_failures (ip);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Аудитории, которые создаются при первой инициализации базы.
INITIAL_AUDITORIUMS = [1, 3, 4, 5, 6]

CATEGORIES = {
    "ide": "Среда разработки",
    "editor": "Редактор кода",
    "lang": "Язык / SDK",
    "db": "СУБД",
    "graphics": "Графика / дизайн",
    "3d": "3D / видео",
    "office": "Офис",
    "browser": "Браузер",
    "network": "Сеть",
    "security": "Безопасность",
    "utility": "Утилиты",
    "virtualization": "Виртуализация",
    "other": "Прочее",
}

LICENSE_TYPES = {
    "free": "Бесплатная",
    "opensource": "Open source",
    "commercial": "Коммерческая",
    "edu": "Образовательная",
    "trial": "Пробная",
}

STATUSES = {
    "active": "В работе",
    "repair": "В ремонте",
    "decommissioned": "Списан",
}


TICKET_KINDS = {
    "problem": "Проблема",
    "install": "Установка ПО",
}

TICKET_STATUSES = {
    "new": "Новая",
    "in_progress": "В работе",
    "done": "Выполнена",
    "rejected": "Отклонена",
}
TICKET_OPEN = ("new", "in_progress")


def aud_code(num):
    return f"AUD-{num}"


def pc_hostname(aud_num, pc_num):
    return f"PC-{aud_num:02d}-{pc_num:02d}"


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE"], timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def migrate(conn):
    """Изменения схемы для баз, созданных старыми версиями."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(installations)")}
    if "source" not in cols:
        conn.execute("ALTER TABLE installations ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'")
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(computers)")}
    if "inv_hw_at" not in cols:
        conn.execute("ALTER TABLE computers ADD COLUMN inv_hw_at TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE computers ADD COLUMN inv_sw_at TEXT NOT NULL DEFAULT ''")
        # До этого обновления время выгрузки хранилось только датой в примечании («Инвентаризация: ГГГГ-ММ-ДД»).
        for row in conn.execute("SELECT id, note FROM computers").fetchall():
            m = re.search(r"Инвентаризация:\s*(\d{4}-\d{2}-\d{2})", row["note"] or "")
            if m:
                has_auto = conn.execute("SELECT 1 FROM installations WHERE computer_id = ? AND source = 'auto' LIMIT 1",
                                        (row["id"],)).fetchone()
                conn.execute("UPDATE computers SET inv_hw_at = ?, inv_sw_at = ? WHERE id = ?",
                             (m.group(1), m.group(1) if has_auto else "", row["id"]))
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
    if "position" in cols:  # должности были недолго, потом их убрали
        conn.execute("ALTER TABLE users DROP COLUMN position")
    if "must_change_password" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
    if "reset_requested_at" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN reset_requested_at TEXT NOT NULL DEFAULT ''")
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(tickets)")}
    if "auditorium_id" not in cols:
        conn.execute("ALTER TABLE tickets ADD COLUMN auditorium_id INTEGER "
                     "REFERENCES auditoriums(id) ON DELETE SET NULL")
    if "need_by" not in cols:
        conn.execute("ALTER TABLE tickets ADD COLUMN need_by TEXT NOT NULL DEFAULT ''")
    if "edited_at" not in cols:
        conn.execute("ALTER TABLE tickets ADD COLUMN edited_at TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE tickets ADD COLUMN edited_by TEXT NOT NULL DEFAULT ''")
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(ticket_messages)")}
    if "edited_at" not in cols:
        conn.execute("ALTER TABLE ticket_messages ADD COLUMN edited_at TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE ticket_messages ADD COLUMN system INTEGER NOT NULL DEFAULT 0")
    if "author_id" not in cols:
        conn.execute("ALTER TABLE ticket_messages ADD COLUMN author_id INTEGER")
        # Старые сообщения: автор по имени, если оно однозначно совпадает с одним пользователем.
        conn.execute("""UPDATE ticket_messages SET author_id = (
                            SELECT u.id FROM users u
                             WHERE COALESCE(NULLIF(u.full_name, ''), u.username) = ticket_messages.author_name)
                        WHERE is_admin = 0 AND (
                            SELECT COUNT(*) FROM users u
                             WHERE COALESCE(NULLIF(u.full_name, ''), u.username) = ticket_messages.author_name) = 1""")
    # Автор всегда следит за своей заявкой (раньше непрочитанное автора хранилось в tickets.user_unread).
    conn.execute("""INSERT OR IGNORE INTO ticket_watchers (ticket_id, user_id, unread)
                    SELECT id, author_id, user_unread FROM tickets WHERE author_id IS NOT NULL""")


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    migrate(conn)
    if conn.execute("SELECT COUNT(*) FROM auditoriums").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO auditoriums (num) VALUES (?)",
            [(n,) for n in INITIAL_AUDITORIUMS],
        )
    conn.commit()


def get_setting(key, default=None):
    row = get_db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    conn = get_db()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


# Выборка компьютеров вместе с номером аудитории — используется во многих местах.
COMPUTERS_SQL = """
SELECT c.*, a.num AS aud_num,
       (SELECT COUNT(*) FROM installations i WHERE i.computer_id = c.id) AS sw_count,
       (SELECT MAX(i.installed_at) FROM installations i WHERE i.computer_id = c.id) AS last_install
FROM computers c JOIN auditoriums a ON a.id = c.auditorium_id
"""


def computer_dict(row):
    d = dict(row)
    d["hostname"] = pc_hostname(d["aud_num"], d["num"])
    d["aud_code"] = aud_code(d["aud_num"])
    return d


def parse_hostname(hostname):
    """PC-05-16 -> (5, 16); иначе None."""
    parts = hostname.upper().split("-")
    if len(parts) != 3 or parts[0] != "PC":
        return None
    try:
        return int(parts[1]), int(parts[2])
    except ValueError:
        return None


def parse_aud_code(code):
    """AUD-5 -> 5; иначе None."""
    prefix, _, num = code.upper().partition("-")
    if prefix != "AUD" or not num.isdigit():
        return None
    return int(num)
