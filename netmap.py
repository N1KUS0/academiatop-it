"""Карта ПК в сети: какие компьютеры сейчас отвечают на ping.

IP компьютера берётся из примечания («IP: 10.0.3.15» — его пишет автовыгрузка инвентаризации,
можно вписать и вручную). На Linux все ПК пингуются разом через один ICMP-сокет без прав root
(Debian разрешает их всем через net.ipv4.ping_group_range), иначе — командой ping параллельно.
Результат кэшируется на CACHE_SECONDS, чтобы главная страница у многих людей не пинговала сеть каждый раз.
"""
import ipaddress
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
_cache = {"at": 0.0, "key": None, "result": {}}


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


def _ping_socket(ips, timeout):
    """Все адреса одним ICMP-сокетом (SOCK_DGRAM, Linux). {ip: время ответа в мс}."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    try:
        sock.setblocking(False)
        sent, alive = {}, {}

        def send_all(only_missing):
            for seq, ip in enumerate(ips, 1):
                if only_missing and ip in alive:
                    continue
                payload = b"academiatop-netmap"
                header = struct.pack("!BBHHH", 8, 0, 0, 0, seq & 0xFFFF)  # идентификатор ставит ядро
                packet = struct.pack("!BBHHH", 8, 0, _checksum(header + payload), 0, seq & 0xFFFF) + payload
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
                    data, (src, _port) = sock.recvfrom(1024)
                except BlockingIOError:
                    break
                except OSError:
                    break
                if data and data[0] == 0 and src in sent and src not in alive:  # echo reply
                    alive[src] = round((time.monotonic() - sent[src]) * 1000, 1)
        return alive
    finally:
        sock.close()


def _ping_command(ip, timeout):
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        started = time.monotonic()
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
    except (OSError, subprocess.TimeoutExpired):
        return None
    # Windows возвращает 0 и на «Заданный узел недоступен», поэтому смотрим на TTL в ответе.
    if r.returncode == 0 and b"TTL=" in r.stdout.upper():
        return round((time.monotonic() - started) * 1000, 1)
    return None


def _ping_commands(ips, timeout):
    with ThreadPoolExecutor(max_workers=min(64, len(ips))) as pool:
        results = pool.map(lambda ip: _ping_command(ip, timeout), ips)
    return {ip: ms for ip, ms in zip(ips, results) if ms is not None}


def ping_many(ips, timeout=TIMEOUT):
    """{ip: мс} для ответивших адресов."""
    ips = sorted(set(ips))
    if not ips:
        return {}
    if hasattr(socket, "IPPROTO_ICMP") and os.name != "nt":
        try:
            return _ping_socket(ips, timeout)
        except PermissionError:
            pass  # ping_group_range запрещает — пробуем командой ping
    return _ping_commands(ips, timeout)


def check(ips):
    """Как ping_many, но с кэшем на CACHE_SECONDS. Возвращает (результат, время проверки)."""
    key = tuple(sorted(set(ips)))
    with _lock:
        if _cache["key"] == key and time.time() - _cache["at"] < CACHE_SECONDS:
            return _cache["result"], _cache["at"]
        result = ping_many(key)
        _cache.update(at=time.time(), key=key, result=result)
        return result, _cache["at"]
