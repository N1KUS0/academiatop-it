"""Карта ПК в сети: какие компьютеры сейчас отвечают на ping.

IP компьютера берётся из примечания («IP: 10.0.3.15» — его пишет автовыгрузка инвентаризации,
можно вписать и вручную). На Linux все ПК пингуются разом через один ICMP-сокет: обычный (если
net.ipv4.ping_group_range разрешает) или raw (служба registry получает для этого CAP_NET_RAW),
в крайнем случае — командой ping параллельно.
Результат кэшируется на CACHE_SECONDS, чтобы главная страница у многих людей не пинговала сеть каждый раз.
"""
import ipaddress
import logging
import os
import re
import select
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 1.0          # сколько ждать ответа, секунд
CACHE_SECONDS = 20

_IP_RE = re.compile(r"\bIP:\s*([^;]+)", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_lock = threading.Lock()
_cache = {"at": 0.0, "key": None, "result": {}, "error": None}
log = logging.getLogger(__name__)


def ip_from_note(note):
    """Первый IPv4 из «IP: …» в примечании (адреса 169.254.* и 127.* пропускаются) или None."""
    m = _IP_RE.search(note or "")
    if not m:
        return None
    for candidate in _IPV4_RE.findall(m.group(1)):
        try:
            ip = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        if not (ip.is_link_local or ip.is_loopback or ip.is_unspecified):
            return str(ip)
    return None


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _ping_socket(ips, timeout, raw):
    """Все адреса одним ICMP-сокетом. {ip: время ответа в мс}.

    raw=False — SOCK_DGRAM: без прав, если группа пользователя входит в net.ipv4.ping_group_range;
    raw=True  — SOCK_RAW: нужен CAP_NET_RAW (его даёт служба registry, см. deploy/registry.service).
    """
    kind = socket.SOCK_RAW if raw else socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
    ident = os.getpid() & 0xFFFF  # у SOCK_DGRAM идентификатор всё равно ставит ядро
    try:
        sock.setblocking(False)
        sent, alive = {}, {}
        seq_of = {ip: n for n, ip in enumerate(ips, 1)}

        def send_all(only_missing):
            for ip, seq in seq_of.items():
                if only_missing and ip in alive:
                    continue
                payload = b"academiatop-netmap"
                header = struct.pack("!BBHHH", 8, 0, 0, ident, seq & 0xFFFF)
                packet = struct.pack("!BBHHH", 8, 0, _checksum(header + payload), ident, seq & 0xFFFF) + payload
                try:
                    sock.sendto(packet, (ip, 0))
                    sent.setdefault(ip, time.monotonic())
                except OSError:
                    pass  # нет маршрута и т.п. — просто не в сети

        send_all(False)
        start = time.monotonic()
        resent = False
        while len(alive) < len(sent):
            left = timeout - (time.monotonic() - start)
            if left <= 0:
                break
            if not resent and left < timeout / 2:
                send_all(True)  # второй запрос тем, кто молчит: один пакет мог потеряться
                resent = True
            ready, _, _ = select.select([sock], [], [], min(left, timeout / 2))
            if not ready:
                continue
            while True:
                try:
                    data, (src, _port) = sock.recvfrom(2048)
                except OSError:  # нет данных (BlockingIOError) или пришла ошибка ICMP
                    break
                if raw:  # в raw-сокет приходит и IP-заголовок, и чужие ICMP-пакеты
                    data = data[(data[0] & 0x0F) * 4:] if data else b""
                    if len(data) < 8 or struct.unpack("!H", data[4:6])[0] != ident:
                        continue
                if data and data[0] == 0 and src in sent and src not in alive:  # echo reply
                    alive[src] = round((time.monotonic() - sent[src]) * 1000, 1)
        if not sent:
            raise OSError("не удалось отправить ни одного ICMP-пакета")
        return alive
    finally:
        sock.close()


class PingUnavailable(Exception):
    """Сервер не может пинговать: нет прав на ICMP."""


_ERROR = object()


def _ping_command(ip, timeout):
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        started = time.monotonic()
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return _ERROR
    # Windows возвращает 0 и на «Заданный узел недоступен», поэтому смотрим на TTL в ответе.
    if r.returncode == 0 and b"TTL=" in r.stdout.upper():
        return round((time.monotonic() - started) * 1000, 1)
    # Linux: 1 — ответа нет, 2 и больше — ошибка самого ping (например, «Operation not permitted»).
    return _ERROR if os.name != "nt" and r.returncode >= 2 else None


def _ping_commands(ips, timeout):
    with ThreadPoolExecutor(max_workers=min(64, len(ips))) as pool:
        results = list(pool.map(lambda ip: _ping_command(ip, timeout), ips))
    if all(ms is _ERROR for ms in results):
        raise PingUnavailable("команда ping не работает от имени службы")
    return {ip: ms for ip, ms in zip(ips, results) if ms is not None and ms is not _ERROR}


def ping_many(ips, timeout=TIMEOUT, explain=None):
    """{ip: мс} для ответивших адресов. Если пинговать нечем — PingUnavailable.

    explain — список, куда записывается, какие способы пробовались (для команды netmap-check).
    """
    ips = sorted(set(ips))
    if not ips:
        return {}
    note = explain.append if explain is not None else (lambda _msg: None)
    if os.name != "nt" and hasattr(socket, "IPPROTO_ICMP"):
        for raw, name in ((False, "ICMP-сокет без прав (ping_group_range)"), (True, "raw ICMP-сокет (CAP_NET_RAW)")):
            try:
                result = _ping_socket(ips, timeout, raw)
                note(f"{name}: работает")
                return result
            except OSError as e:
                note(f"{name}: {e}")
    try:
        result = _ping_commands(ips, timeout)
        note("команда ping: работает")
        return result
    except PingUnavailable as e:
        note(f"команда ping: {e}")
        raise PingUnavailable("Сервер не может отправлять ping: у службы нет прав на ICMP. "
                              "Обновите сайт (deploy/update.sh) — служба получит CAP_NET_RAW.") from None


def check(ips):
    """Как ping_many, но с кэшем на CACHE_SECONDS. Возвращает (результат, время проверки, ошибка или None)."""
    key = tuple(sorted(set(ips)))
    with _lock:
        if _cache["key"] == key and time.time() - _cache["at"] < CACHE_SECONDS:
            return _cache["result"], _cache["at"], _cache["error"]
        try:
            result, error = ping_many(key), None
        except PingUnavailable as e:
            result, error = {}, str(e)
            log.error("netmap: %s", e)
        _cache.update(at=time.time(), key=key, result=result, error=error)
        return result, _cache["at"], error


# --------------------------------------------------------------------------- Wake-on-LAN

_MAC_SECTION_RE = re.compile(r"\bMAC:\s*([^;]+)", re.IGNORECASE)
_MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
WOL_PORT = 9


def macs_from_note(note):
    """MAC-адреса из «MAC: …» в примечании (их может быть несколько — у ПК бывает не одна сетевая карта)."""
    m = _MAC_SECTION_RE.search(note or "")
    if not m:
        return []
    macs = []
    for raw in _MAC_RE.findall(m.group(1)):
        mac = raw.replace("-", ":").upper()
        if mac not in macs and mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            macs.append(mac)
    return macs


def wake(macs, ip=None):
    """Отправляет «магический пакет» Wake-on-LAN на каждый MAC.

    Пакет уходит широковещательно (255.255.255.255) и, если IP ПК известен, ещё в широковещательный адрес
    его сети /24 — на случай, если у сервера несколько сетевых интерфейсов. Возвращает число отправленных пакетов.
    """
    targets = ["255.255.255.255"]
    if ip:
        targets.append(ip.rsplit(".", 1)[0] + ".255")
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for mac in macs:
            packet = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16
            for addr in targets:
                try:
                    sock.sendto(packet, (addr, WOL_PORT))
                    sent += 1
                except OSError:
                    pass  # нет маршрута в эту сеть — хватит другого адреса
    return sent
