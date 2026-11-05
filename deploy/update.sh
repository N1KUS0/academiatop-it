#!/bin/bash
# Быстрое обновление сайта из GitHub: git pull, копия базы, копирование файлов, перезапуск.
# Пакеты не ставит — для первой установки нужен deploy/install.sh.
# Запуск из папки клона репозитория:  bash deploy/update.sh   (--force — обновить, даже если новых коммитов нет)
set -euo pipefail

# Тело в { } — bash прочитает скрипт целиком, и git pull может спокойно заменить этот файл.
{
APP_DIR=/opt/registry
DB="$APP_DIR/instance/registry.db"
BACKUP_DIR=/var/backups/registry
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FORCE="${1:-}"

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO=sudo

if [ ! -x "$APP_DIR/.venv/bin/pip" ]; then
    echo "Сайт ещё не установлен. Сначала: sudo bash deploy/install.sh" >&2
    exit 1
fi

echo "==> Загрузка изменений из GitHub"
# pull — от владельца клона, чтобы файлы в .git не стали принадлежать root
OWNER="$(stat -c %U "$SRC_DIR")"
git_src() {
    if [ "$(id -un)" = "$OWNER" ]; then git -C "$SRC_DIR" "$@"; else sudo -u "$OWNER" git -C "$SRC_DIR" "$@"; fi
}
git_src pull --ff-only
NEW="$(git_src rev-parse HEAD)"
# Сравниваем с тем, что реально стоит на сайте, а не с прошлым git pull:
# если прошлое обновление сорвалось (например, pip без сети), этот запуск его доделает.
DEPLOYED_FILE="$APP_DIR/instance/deployed-commit"
DEPLOYED="$($SUDO cat "$DEPLOYED_FILE" 2>/dev/null || true)"
if [ "$DEPLOYED" = "$NEW" ] && [ "$FORCE" != "--force" ]; then
    echo "Новых изменений нет, на сервере уже $(git_src log -1 --format='%h %s')."
    echo "Переустановить всё равно: bash deploy/update.sh --force"
    exit 0
fi

echo "==> Копия базы перед обновлением"
$SUDO mkdir -p "$BACKUP_DIR"
if [ -f "$DB" ]; then
    $SUDO sqlite3 "$DB" ".backup '$BACKUP_DIR/pre-update-$(date +%F-%H%M%S).db'"
    # храним 10 последних копий перед обновлениями
    ls -1t "$BACKUP_DIR"/pre-update-*.db | tail -n +11 | $SUDO xargs -r rm --
fi

# Что изменилось из настроек сервера — сравниваем до копирования.
SERVICE_CHANGED=0; NGINX_CHANGED=0
cmp -s "$SRC_DIR/deploy/registry.service" /etc/systemd/system/registry.service || SERVICE_CHANGED=1
cmp -s "$SRC_DIR/deploy/nginx-registry.conf" /etc/nginx/sites-available/registry || NGINX_CHANGED=1
BACKUP_TIMER_CHANGED=0
for unit in registry-backup.service registry-backup.timer; do
    cmp -s "$SRC_DIR/deploy/$unit" "/etc/systemd/system/$unit" || BACKUP_TIMER_CHANGED=1
done

# Зависимости ставим до копирования: если pip не сработает, сайт останется на прежней версии,
# а следующий запуск попробует снова. Уже установленное pip не скачивает заново — это быстро.
echo "==> Зависимости Python"
if ! $SUDO "$APP_DIR/.venv/bin/pip" install -q -r "$SRC_DIR/requirements.txt"; then
    echo "Не удалось установить зависимости Python (нужен доступ к pypi.org). Сайт не обновлён." >&2
    exit 1
fi

echo "==> Копирование файлов в $APP_DIR"
$SUDO rsync -a --delete \
    --exclude '.venv' --exclude 'instance' --exclude '__pycache__' --exclude '.claude' --exclude '.git' --exclude '*.zip' \
    "$SRC_DIR/" "$APP_DIR/"
$SUDO chmod +x "$APP_DIR/deploy/"*.sh

if [ "$SERVICE_CHANGED" = 1 ]; then
    echo "==> systemd: служба изменилась"
    $SUDO cp "$APP_DIR/deploy/registry.service" /etc/systemd/system/registry.service
    $SUDO systemctl daemon-reload
fi

if [ "$BACKUP_TIMER_CHANGED" = 1 ]; then
    echo "==> systemd: копия базы в Telegram каждый день в 00:00"
    $SUDO cp "$APP_DIR/deploy/registry-backup.service" "$APP_DIR/deploy/registry-backup.timer" /etc/systemd/system/
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now registry-backup.timer
fi

echo "==> Перезапуск"
$SUDO systemctl restart registry

if [ "$NGINX_CHANGED" = 1 ]; then
    echo "==> nginx: конфиг изменился"
    $SUDO cp "$APP_DIR/deploy/nginx-registry.conf" /etc/nginx/sites-available/registry
    $SUDO nginx -t
    $SUDO systemctl reload nginx
fi

sleep 2
if ! $SUDO systemctl is-active --quiet registry; then
    echo "Служба не запустилась. Последние строки журнала:" >&2
    $SUDO journalctl -u registry -n 30 --no-pager >&2
    echo "Копия базы до обновления — в $BACKUP_DIR (pre-update-*.db)." >&2
    exit 1
fi

echo "$NEW" | $SUDO tee "$DEPLOYED_FILE" >/dev/null

echo
echo "Готово: $(git_src log -1 --format='%h %s')"
if [ -n "$DEPLOYED" ] && [ "$DEPLOYED" != "$NEW" ] && git_src cat-file -e "$DEPLOYED^{commit}" 2>/dev/null; then
    echo "Изменения:"
    git_src log --format='  %h %s' "$DEPLOYED..$NEW"
fi
exit 0
}
