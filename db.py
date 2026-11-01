"""Работа с базой SQLite: схема, подключение, справочники."""
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
    author_id       INTEGER,                           -- users.id; NULL — администратор или удалённый пользователь
    author_username TEXT NOT NULL DEFAULT '',
    author_name     TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    admin_unread    INTEGER NOT NULL DEFAULT 1,        -- есть новое для администратора
    user_unread     INTEGER NOT NULL DEFAULT 0         -- есть новое для автора
);
CREATE INDEX IF NOT EXISTS tickets_author ON tickets (author_id);

CREATE TABLE IF NOT EXISTS ticket_messages (
    id          INTEGER PRIMARY KEY,
    ticket_id   INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_name TEXT NOT NULL DEFAULT '',
    is_admin    INTEGER NOT NULL DEFAULT 0,
    body        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',   -- новый статус, если сообщение его меняло
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ticket_messages_ticket ON ticket_messages (ticket_id);

-- Кто следит за заявкой: автор и те, кого она «тоже касается». unread — есть новое для этого пользователя.
CREATE TABLE IF NOT EXISTS ticket_watchers (
    ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL,
    unread    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ticket_id, user_id)
);
CREATE INDEX IF NOT EXISTS ticket_watchers_user ON ticket_watchers (user_id);

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
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
    if "position" in cols:  # должности были недолго, потом их убрали
        conn.execute("ALTER TABLE users DROP COLUMN position")
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(tickets)")}
    if "auditorium_id" not in cols:
        conn.execute("ALTER TABLE tickets ADD COLUMN auditorium_id INTEGER "
                     "REFERENCES auditoriums(id) ON DELETE SET NULL")
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
