"""Карта ПК в сети: какие компьютеры сейчас отвечают на ping.

Адреса ПК: из DNS по имени ПК и все IP из примечания («IP: 10.0.3.15» — его пишет автовыгрузка
инвентаризации, можно вписать и вручную). ПК в сети, если ответил любой из них. На Linux все ПК пингуются разом через один ICMP-сокет: обычный (если
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
from concurrent.futures import ThreadPoolExecutor, wait

TIMEOUT = 1.0          # сколько ждать ответа, секунд
CACHE_SECONDS = 20

DNS_TIMEOUT = 2.0      # сколько ждать DNS, секунд
DNS_CACHE_SECONDS = 300

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_AD_NAME_RE = re.compile(r"\bв AD:\s*([A-Za-z0-9-]+)")
# Продолжение поля: пункт из одних адресов («192.168.99.166», «AA-BB-…»), без своей подписи вида «Плата:».
_CONTINUATION_RE = re.compile(r"^[\s0-9A-Fa-f:.,/-]+$")

_lock = threading.Lock()
_cache = {"at": 0.0, "key": None, "result": {}, "error": None}
_dns_lock = threading.Lock()
_dns_cache = {}  # имя -> (когда проверено, IP или None)
log = logging.getLogger(__name__)


def note_field(note, label):
    """Значение поля «label: …» примечания. Пункты разделены «; », а несколько адресов в поле тоже бывают
    через «;» — такие пункты без своей подписи считаются продолжением поля."""
    items = (note or "").split(";")
    for i, item in enumerate(items):
        key, sep, value = item.partition(":")
        if sep and key.strip().upper() == label.upper():
            values = [value]
            for nxt in items[i + 1:]:
                if not _CONTINUATION_RE.match(nxt):
                    break
                values.append(nxt)
            return ";".join(values)
    return ""


def ips_from_note(note):
    """Все IPv4 из «IP: …» в примечании (169.254.*, 127.* и 0.0.0.0 пропускаются)."""
    ips = []
    for candidate in _IPV4_RE.findall(note_field(note, "IP")):
        try:
            ip = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        if not (ip.is_link_local or ip.is_loopback or ip.is_unspecified) and str(ip) not in ips:
            ips.append(str(ip))
    return ips


def ip_from_note(note):
    """Первый IPv4 из «IP: …» в примечании или None."""
    ips = ips_from_note(note)
    return ips[0] if ips else None


def ad_name(hostname, note):
    """Имя ПК в AD/DNS: у ПК преподавателя оно своё (PC-03-ADMIN, см. «в AD: …» в примечании)."""
    m = _AD_NAME_RE.search(note or "")
    return m.group(1) if m else hostname


def _resolve(name):
    try:
        for *_rest, addr in socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM):
            ip = ipaddress.IPv4Address(addr[0])
            if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified):
                return str(ip)
    except (OSError, UnicodeError, ValueError):
        pass
    return None


def resolve_many(names, timeout=DNS_TIMEOUT):
    """{имя: IP} по DNS (короткие имена дополняются доменом поиска сервера, как у команды ping).

    Ответы помнятся DNS_CACHE_SECONDS (ненайденные — минуту). Кто не ответил за timeout, в этот раз пропускается.
    """
    now = time.time()
    result, todo = {}, []
    with _dns_lock:
        for name in set(names):
            cached = _dns_cache.get(name)
            if cached and now - cached[0] < (DNS_CACHE_SECONDS if cached[1] else 60):
                result[name] = cached[1]
            else:
                todo.append(name)
    if todo:
        pool = ThreadPoolExecutor(max_workers=min(32, len(todo)))
        futures = {pool.submit(_resolve, name): name for name in todo}
        done, _ = wait(futures, timeout=timeout)
        pool.shutdown(wait=False)  # зависшие запросы DNS досчитаются в фоне, страницу они не держат
        with _dns_lock:
            for f in done:
                _dns_cache[futures[f]] = (now, f.result())
                result[futures[f]] = f.result()
    return {name: ip for name, ip in result.items() if ip}


def candidates(computers):
    """{hostname: [(ip, откуда)]} для ПК, кроме списанных: адрес из DNS по имени ПК и все IP из примечания."""
    pcs = [c for c in computers if c["status"] != "decommissioned"]
    dns = resolve_many(ad_name(c["hostname"], c["note"]) for c in pcs)
    out = {}
    for c in pcs:
        found = []
        name = ad_name(c["hostname"], c["note"])
        if dns.get(name):
            found.append((dns[name], "DNS"))
        for ip in ips_from_note(c["note"]):
            if ip not in (f[0] for f in found):
                found.append((ip, "примечание"))
        if found:
            out[c["hostname"]] = found
    return out


def arp_table():
    """{ip: MAC} из таблицы ARP сервера (только Linux). После ответа на ping в ней есть MAC ответившего,
    если он в той же сети, что и сервер."""
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                # IP, тип, флаги (0x2 — запись полная), MAC, маска, интерфейс
                if len(parts) >= 4 and int(parts[2], 16) & 0x2:
                    table[parts[0]] = parts[3].upper()
    except (OSError, ValueError):
        pass
    return table


def _ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0].upper()
    except (OSError, UnicodeError):
        return None


def status(computers):
    """Кто из ПК в сети. -> (результат, время проверки, ошибка или None, подробности).

    результат: {hostname: {"ip": ..., "ms": ...}} для ответивших; ПК без адресов в нём нет, а
    подробности {hostname: [(ip, откуда, итог)]} — для команды netmap-check.

    Ответ засчитывается этому ПК, если:
      * MAC ответившего (из ARP) совпал с MAC из примечания — самая надёжная проверка; не совпал — это чужой ПК;
      * иначе, если адрес числится только за этим ПК;
      * иначе (адрес записан на несколько ПК — DHCP выдал его другому, а старая запись в DNS осталась)
        — если обратная запись DNS (PTR) указывает на имя этого ПК.
    """
    by_host = candidates(computers)
    alive, checked_at, error = check(ip for found in by_host.values() for ip, _src in found)
    owners = {}
    for host, found in by_host.items():
        for ip, _src in found:
            owners.setdefault(ip, set()).add(host)
    arp = arp_table() if alive else {}
    notes = {c["hostname"]: c["note"] for c in computers}
    # PTR нужен только для ответивших адресов, записанных на несколько ПК; запросы — параллельно и не дольше DNS_TIMEOUT.
    shared = [ip for ip, hosts in owners.items() if len(hosts) > 1 and ip in alive]
    ptr_cache = {ip: None for ip in shared}
    if shared and not error:
        pool = ThreadPoolExecutor(max_workers=min(16, len(shared)))
        futures = {pool.submit(_ptr, ip): ip for ip in shared}
        done, _ = wait(futures, timeout=DNS_TIMEOUT)
        pool.shutdown(wait=False)
        for f in done:
            ptr_cache[futures[f]] = f.result()
    result, details = {}, {}
    for host, found in by_host.items():
        macs = macs_from_note(notes.get(host, ""))
        details[host] = []
        for ip, src in found:
            if error:
                verdict = "не проверен"
            elif ip not in alive:
                verdict = "нет ответа"
            elif macs and ip in arp:
                verdict = "ответил, MAC совпал" if arp[ip] in macs else f"ответил чужой ПК (MAC {arp[ip]})"
            elif len(owners[ip]) == 1:
                verdict = "ответил"
            else:
                name = ad_name(host, notes.get(host, "")).upper()
                others = ", ".join(sorted(owners[ip] - {host}))
                verdict = (f"ответил, по PTR это он (адрес записан ещё на {others})" if ptr_cache[ip] == name
                           else f"ответил, но адрес записан ещё на {others}, а PTR: {ptr_cache[ip] or 'нет'}")
            details[host].append((ip, src, verdict))
            if verdict.startswith("ответил") and not verdict.startswith(("ответил чужой", "ответил, но")):
                if host not in result or alive[ip] < result[host]["ms"]:
                    result[host] = {"ip": ip, "ms": alive[ip]}
    return result, checked_at, error, details


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
_WIN_TIME_RE = re.compile(rb"[=<]([\d.]+)\S*\s+TTL=", re.IGNORECASE)
_LINUX_TIME_RE = re.compile(rb"time[=<]([\d.]+)")


def _ping_command(ip, timeout):
    # Два запроса: один пакет может потеряться.
    if os.name == "nt":
        cmd = ["ping", "-n", "2", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "2", "-i", "0.2", "-W", str(max(1, int(timeout))), ip]
    try:
        started = time.monotonic()
        r = subprocess.run(cmd, capture_output=True, timeout=2 * timeout + 2)
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return _ERROR
    # Windows возвращает 0 и на «Заданный узел недоступен», поэтому смотрим на TTL в ответе.
    if r.returncode == 0 and b"TTL=" in r.stdout.upper():
        # Время из вывода: Windows «время=31мс TTL=…» (любой язык), Linux «ttl=64 time=0.44 ms».
        m = _WIN_TIME_RE.search(r.stdout) or _LINUX_TIME_RE.search(r.stdout)
        return float(m.group(1)) if m else round((time.monotonic() - started) * 1000 / 2, 1)
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

_MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
WOL_PORT = 9


def macs_from_note(note):
    """MAC-адреса из «MAC: …» в примечании (их может быть несколько — у ПК бывает не одна сетевая карта)."""
    macs = []
    for raw in _MAC_RE.findall(note_field(note, "MAC")):
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
