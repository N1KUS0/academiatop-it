#!/bin/bash
# Установка / обновление «Академии ТОП» на Debian 12.
# Запуск из папки проекта:  sudo bash deploy/install.sh
set -euo pipefail

APP_DIR=/opt/registry
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Запустите через sudo" >&2
    exit 1
fi

echo "==> Пакеты"
apt-get update -q
apt-get install -y -q python3 python3-venv nginx rsync sqlite3 samba-common-bin

echo "==> Пользователь registry"
id registry >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin registry

echo "==> Копирование файлов в $APP_DIR"
mkdir -p "$APP_DIR/instance"
rsync -a --delete \
    --exclude '.venv' --exclude 'instance' --exclude '__pycache__' --exclude '.claude' --exclude '.git' --exclude '*.zip' \
    "$SRC_DIR/" "$APP_DIR/"
chmod +x "$APP_DIR/deploy/"*.sh

echo "==> Виртуальное окружение"
[ -d "$APP_DIR/.venv" ] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

chown -R registry:registry "$APP_DIR/instance"
chmod 750 "$APP_DIR/instance"

echo "==> systemd"
cp "$APP_DIR/deploy/registry.service" /etc/systemd/system/registry.service
systemctl daemon-reload
systemctl enable --now registry
systemctl restart registry
# Копия базы в Telegram каждый день в 00:00 (если Telegram настроен на странице «Данные»)
cp "$APP_DIR/deploy/registry-backup.service" "$APP_DIR/deploy/registry-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now registry-backup.timer

echo "==> nginx"
cp "$APP_DIR/deploy/nginx-registry.conf" /etc/nginx/sites-available/registry
ln -sf /etc/nginx/sites-available/registry /etc/nginx/sites-enabled/registry
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

# Какая версия установлена — по ней deploy/update.sh понимает, есть ли что обновлять.
git -c safe.directory="$SRC_DIR" -C "$SRC_DIR" rev-parse HEAD > "$APP_DIR/instance/deployed-commit" 2>/dev/null \
    || rm -f "$APP_DIR/instance/deployed-commit"

echo
echo "Готово. Сайт: http://$(hostname -I | awk '{print $1}')/"
if ! sudo -u registry REGISTRY_DB="$APP_DIR/instance/registry.db" \
        "$APP_DIR/.venv/bin/python" -c "
import sys; sys.path.insert(0, '$APP_DIR')
from app import app; import db
with app.app_context(): sys.exit(0 if db.get_setting('admin_password') else 1)" 2>/dev/null; then
    echo
    echo "Пароль администратора ещё не задан. Задайте его командой:"
    echo "  cd $APP_DIR && sudo -u registry REGISTRY_DB=$APP_DIR/instance/registry.db .venv/bin/flask --app app set-password"
fi
