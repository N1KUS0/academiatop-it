#!/bin/bash
# Настройка зеркала «Академии ТОП» на VPS (academiatop-blg.ru → туннель AmneziaWG → академия).
# Не трогает другие сайты (map.academiatop-blg.ru и т.д.).
#
#   sudo bash setup-mirror.sh <IP сервера академии в туннеле> [email для Let's Encrypt]
#   пример: sudo bash setup-mirror.sh 10.77.88.2
set -euo pipefail

DOMAIN=academiatop-blg.ru
WG_IP="${1:-}"
EMAIL="${2:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SITE=/etc/nginx/sites-available/registry-mirror
LINK=/etc/nginx/sites-enabled/registry-mirror

if [ "$(id -u)" -ne 0 ]; then echo "Запустите через sudo" >&2; exit 1; fi
if ! [[ "$WG_IP" =~ ^10\.77\.88\.[0-9]{1,3}$ ]]; then
    echo "Укажите IP сервера академии в туннеле 10.77.88.0/24, например: sudo bash $0 10.77.88.2" >&2
    exit 1
fi

echo "==> Проверка связи с академией через туннель ($WG_IP)"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$WG_IP/" || true)
if [ "$code" != "200" ]; then
    echo "   Реестр по http://$WG_IP/ не отвечает (код: ${code:-нет ответа})."
    echo "   Проверьте туннель (ping $WG_IP) и что на сервере академии запущен nginx."
    read -r -p "   Продолжить всё равно? [y/N] " ans
    [[ "$ans" =~ ^[YyДд]$ ]] || exit 1
else
    echo "   OK"
fi

echo "==> Проверка, что $DOMAIN не занят другим конфигом nginx"
if grep -RlsE "server_name[^;]*[[:space:]]$DOMAIN([[:space:]]|;)" /etc/nginx/sites-enabled /etc/nginx/conf.d \
        | grep -v "registry-mirror" ; then
    echo "   Домен $DOMAIN уже указан в файлах выше. Уберите его оттуда и запустите скрипт снова." >&2
    exit 1
fi

echo "==> Проверка DNS: записи $DOMAIN должны указывать на этот VPS"
local_ips=" $(hostname -I) "
public_v4=$(curl -4 -s --max-time 5 https://ifconfig.me || true)
dns_ok=1
for fam in v4 v6; do
    for ip in $(getent "ahosts$fam" "$DOMAIN" | awk '{print $1}' | sort -u); do
        [ "$fam" = v4 ] && [[ "$ip" == *:* ]] && continue   # ahostsv4 может вернуть ::ffff:-адреса
        if [[ "$local_ips" == *" $ip "* ]] || [ "$ip" = "$public_v4" ]; then
            echo "   $ip — OK"
        else
            echo "   $ip — НЕ этот сервер"
            dns_ok=0
        fi
    done
done
if [ "$dns_ok" -ne 1 ]; then
    echo "   Исправьте записи A/AAAA у регистратора: лишнюю AAAA (IPv6) удалите или укажите IPv6 этого VPS."
    echo "   Иначе Let's Encrypt не сможет проверить домен."
    read -r -p "   Продолжить всё равно? [y/N] " ans
    [[ "$ans" =~ ^[YyДд]$ ]] || exit 1
fi

echo "==> Пакеты"
command -v certbot >/dev/null || { apt-get update -q && apt-get install -y -q certbot; }

mkdir -p /var/www/letsencrypt /var/www/registry-mirror
cp "$HERE/offline.html" /var/www/registry-mirror/offline.html

# Если что-то пойдёт не так — убираем свой конфиг, чтобы не сломать остальные сайты.
rollback() {
    echo "!! Ошибка, откатываю конфиг зеркала" >&2
    rm -f "$LINK"
    nginx -t 2>/dev/null && systemctl reload nginx
}
trap rollback ERR

if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "==> Получение сертификата Let's Encrypt"
    # Временный конфиг только на 80 порту — для проверки домена.
    sed -n '/^server {/,/^}/p' "$HERE/academiatop-blg.ru.conf" | sed -n '1,/^}/p' > "$SITE"
    ln -sf "$SITE" "$LINK"
    nginx -t && systemctl reload nginx
    if [ -n "$EMAIL" ]; then mail_opt=(-m "$EMAIL"); else mail_opt=(--register-unsafely-without-email); fi
    certbot certonly --webroot -w /var/www/letsencrypt -d "$DOMAIN" \
        --non-interactive --agree-tos "${mail_opt[@]}"
fi

echo "==> Конфиг nginx"
sed "s/__ACADEMY_WG_IP__/$WG_IP/" "$HERE/academiatop-blg.ru.conf" > "$SITE"
ln -sf "$SITE" "$LINK"
nginx -t
systemctl reload nginx
trap - ERR

# Перезагрузка nginx после автопродления сертификата.
HOOK=/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
if [ ! -f "$HOOK" ]; then
    mkdir -p "$(dirname "$HOOK")"
    printf '#!/bin/sh\nsystemctl reload nginx\n' > "$HOOK"
    chmod +x "$HOOK"
fi

echo
echo "Готово: https://$DOMAIN/ (вход для администратора — кнопка «Войти»)"
