"""Выключение ПК по сети: команда `net rpc shutdown` из Samba (пакет samba-common-bin).

Это тот же удалённый вызов, что `shutdown /s /m \\\\ПК` в Windows: подключение к ПК по SMB (порт 445)
от имени доменной учётной записи с правами администратора на ПК.

Учётная запись хранится не в базе (база каждый день уходит в Telegram), а в отдельном файле
instance/shutdown.auth с правами 600. Задаётся командой `flask --app app set-shutdown-account`.
"""
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

AUTH_NAME = "shutdown.auth"
DELAY = 60          # секунд до выключения: пользователь увидит предупреждение и успеет сохранить работу
TIMEOUT = 20        # сколько ждать ответа ПК, секунд
MESSAGE = "Компьютер будет выключен администратором через 1 минуту. Сохраните работу."

# Частые ошибки Samba -> понятный текст.
ERRORS = [
    ("NT_STATUS_LOGON_FAILURE", "неверный логин или пароль учётной записи для выключения"),
    ("NT_STATUS_ACCOUNT_LOCKED_OUT", "учётная запись для выключения заблокирована"),
    ("NT_STATUS_PASSWORD_EXPIRED", "у учётной записи для выключения истёк пароль"),
    ("NT_STATUS_ACCESS_DENIED", "нет прав: учётная запись должна быть администратором на этом ПК"),
    ("NT_STATUS_IO_TIMEOUT", "ПК не ответил на порту 445 — включён ли он, не закрыт ли брандмауэром"),
    ("NT_STATUS_CONNECTION_REFUSED", "ПК не принимает подключение на порту 445 (брандмауэр)"),
    ("NT_STATUS_HOST_UNREACHABLE", "ПК недоступен по сети"),
    ("NT_STATUS_NETWORK_UNREACHABLE", "сеть ПК недоступна с сервера"),
    ("NT_STATUS_SHUTDOWN_IN_PROGRESS", "ПК уже выключается"),
]


def auth_path(instance_dir):
    return os.path.join(instance_dir, AUTH_NAME)


def load_account(instance_dir):
    """{"domain": ..., "username": ...} заданной учётной записи (без пароля) или None."""
    try:
        with open(auth_path(instance_dir), encoding="utf-8") as f:
            fields = dict(line.split("=", 1) for line in f.read().splitlines() if "=" in line)
    except OSError:
        return None
    fields = {k.strip(): v.strip() for k, v in fields.items()}
    if not fields.get("username") or not fields.get("password"):
        return None
    return {"domain": fields.get("domain", ""), "username": fields["username"]}


def save_account(instance_dir, domain, username, password):
    """Файл учётных данных в формате `net -A` (username/password/domain), доступный только владельцу."""
    for value in (domain, username, password):
        if "\n" in value or "\r" in value:
            raise ValueError("Перевод строки в учётных данных недопустим.")
    path = auth_path(instance_dir)
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(f"username = {username}\npassword = {password}\n" + (f"domain = {domain}\n" if domain else ""))
    os.replace(path + ".tmp", path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def delete_account(instance_dir):
    try:
        os.remove(auth_path(instance_dir))
        return True
    except FileNotFoundError:
        return False


def _smb_conf(instance_dir):
    """Свой smb.conf с каталогами внутри instance/: служба registry не может писать в /var (ProtectSystem=strict)."""
    base = os.path.join(instance_dir, "samba")
    dirs = {name: os.path.join(base, name) for name in ("cache", "lock", "state", "private", "ncalrpc")}
    for d in dirs.values():
        os.makedirs(d, mode=0o700, exist_ok=True)
    path = os.path.join(base, "smb.conf")
    text = ("[global]\n"
            f"  cache directory = {dirs['cache']}\n"
            f"  lock directory = {dirs['lock']}\n"
            f"  state directory = {dirs['state']}\n"
            f"  private dir = {dirs['private']}\n"
            f"  ncalrpc dir = {dirs['ncalrpc']}\n"
            "  disable netbios = yes\n"
            "  client min protocol = SMB2\n")
    try:
        with open(path, encoding="utf-8") as f:
            if f.read() == text:
                return path
    except OSError:
        pass
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def explain(output):
    for code, text in ERRORS:
        if code in output:
            return text
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1][:200] if lines else "неизвестная ошибка"


def shutdown(ip, instance_dir, delay=DELAY, message=MESSAGE):
    """Выключить ПК по IP. -> (успех, текст ошибки или "")."""
    if not load_account(instance_dir):
        return False, "не задана учётная запись для выключения (см. страницу «Данные»)"
    cmd = ["net", "rpc", "shutdown", "-I", ip, "-A", auth_path(instance_dir), "-s", _smb_conf(instance_dir),
           "-f", "-t", str(delay), "-C", message]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT)
    except FileNotFoundError:
        return False, "на сервере нет программы net: sudo apt install samba-common-bin"
    except subprocess.TimeoutExpired:
        return False, f"ПК не ответил за {TIMEOUT} с"
    out = (r.stdout + r.stderr).decode("utf-8", errors="replace")
    # При успехе net пишет «Shutdown of remote machine succeeded» и выходит с 0, при ошибке — не 0.
    # Предупреждения (например, про кэш) бывают и при успехе, поэтому смотрим только на код выхода.
    if r.returncode == 0:
        return True, ""
    return False, explain(out)


def shutdown_many(ips, instance_dir, delay=DELAY, message=MESSAGE):
    """{ip: (успех, текст)} — параллельно, чтобы аудитория выключалась не дольше одного ПК."""
    ips = list(dict.fromkeys(ips))
    if not ips:
        return {}
    with ThreadPoolExecutor(max_workers=min(16, len(ips))) as pool:
        results = pool.map(lambda ip: shutdown(ip, instance_dir, delay, message), ips)
    return dict(zip(ips, results))
