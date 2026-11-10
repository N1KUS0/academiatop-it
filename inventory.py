"""Импорт автовыгрузки инвентаризации (inventory_latest.zip) в реестр.

Архив содержит computers.csv (железо) и software_raw.csv (установленное ПО), разделитель «;», UTF-8.
Данные приводятся к тому же виду, в каком их вносили вручную, и записываются в базу.
"""
import csv
import io
import json
import re
import zipfile
from datetime import datetime, timedelta

import history
from inventory_rules import CATALOG, NAME, NONE, RAW, RULES, YEAR

COMPILED_RULES = [(re.compile(p, re.IGNORECASE), canon, ver, use_date) for p, canon, ver, use_date in RULES]

# ПК преподавателя в AD называется PC-03-ADMIN, в реестре — PC-03-99.
ADMIN_PC_NUM = 99


# --------------------------------------------------------------------------- чтение архива

class InventoryError(Exception):
    pass


def read_archive(data):
    """bytes/путь к zip -> (computers: list[dict], software: list[dict])."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data) if isinstance(data, bytes) else data)
    except zipfile.BadZipFile:
        raise InventoryError("Файл не является zip-архивом.")
    names = {n.rsplit("/", 1)[-1].lower(): n for n in zf.namelist()}
    for need in ("computers.csv", "software_raw.csv"):
        if need not in names:
            raise InventoryError(f"В архиве нет файла {need}.")

    def rows(name):
        raw = zf.read(names[name])
        if len(raw) > 50 * 1024 * 1024:
            raise InventoryError(f"{name} слишком большой.")
        text = raw.decode("utf-8-sig", errors="replace")
        return [{k: (v or "").strip() for k, v in r.items() if k}
                for r in csv.DictReader(io.StringIO(text), delimiter=";")]

    computers, software = rows("computers.csv"), rows("software_raw.csv")
    if computers and "Hostname" not in computers[0]:
        raise InventoryError("В computers.csv нет колонки Hostname.")
    if software and not {"Hostname", "Name", "Version"} <= software[0].keys():
        raise InventoryError("В software_raw.csv нет колонок Hostname/Name/Version.")
    return computers, software


# --------------------------------------------------------------------------- компьютеры

def parse_ad_hostname(hostname):
    """PC-03-09 -> (3, 9, False); PC-03-ADMIN -> (3, 99, True); иначе None."""
    m = re.fullmatch(r"PC-(\d{1,2})-(\d{1,2}|ADMIN)", hostname.strip().upper())
    if not m:
        return None
    if m.group(2) == "ADMIN":
        return int(m.group(1)), ADMIN_PC_NUM, True
    return int(m.group(1)), int(m.group(2)), False


def clean_os(os_name):
    return re.sub(r"^(Майкрософт|Microsoft)\s+", "", os_name).strip()


def clean_cpu(cpu, cores, threads):
    s = re.sub(r"\((R|TM)\)", "", cpu, flags=re.IGNORECASE)
    s = re.sub(r"\b\d+(st|nd|rd|th) Gen\b", "", s)
    s = re.sub(r"@.*$", "", s)
    s = re.sub(r"\bCPU\b", "", s)
    s = " ".join(s.split())
    if cores and threads:
        s += f" ({cores}C/{threads}T)"
    return s


def clean_disks(disks):
    parts = []
    for d in disks.split(" + "):
        d = " ".join(d.split())
        m = re.fullmatch(r"(?P<model>.*?)\s+(?P<size>\d+)GB\s+(?P<type>SSD|HDD|\w+)", d)
        parts.append(f"{m['type']} {m['size']} ГБ ({m['model']})" if m else d)
    return " + ".join(p for p in parts if p)


def build_note(r, is_admin, ad_hostname):
    items = []
    if is_admin:
        items.append(f"ПК преподавателя, в AD: {ad_hostname}")
    for label, value in (("Плата", r.get("Board")), ("MAC", r.get("MAC")), ("IP", r.get("IP")),
                         ("ОС установлена", r.get("OSInstallDate"))):
        if value:
            items.append(f"{label}: {value}")
    if r.get("SysDriveFreeGB"):
        items.append(f"Свободно на C: {r['SysDriveFreeGB']} ГБ")
    collected = (r.get("CollectedAt") or "")[:10]
    if collected:
        items.append(f"Инвентаризация: {collected}" + (f" ({r['Source']})" if r.get("Source") else ""))
    return "; ".join(items)


def normalize_computer(r):
    """Строка computers.csv -> поля компьютера в реестре или None, если имя не подходит."""
    parsed = parse_ad_hostname(r.get("Hostname", ""))
    if not parsed:
        return None
    aud_num, pc_num, is_admin = parsed
    os_version = r.get("OSVersion", "")
    if r.get("OSBuild"):
        os_version = f"{os_version} ({r['OSBuild']})" if os_version else r["OSBuild"]
    return {
        "ad_hostname": r["Hostname"].strip().upper(),
        "aud_num": aud_num,
        "num": pc_num,
        "os": clean_os(r.get("OS", "")),
        "os_version": os_version,
        "cpu": clean_cpu(r.get("CPU", ""), r.get("Cores"), r.get("Threads")),
        "ram": f"{r['RAM_GB']} ГБ" if r.get("RAM_GB") else "",
        "disk": clean_disks(r.get("Disks", "")),
        "note": build_note(r, is_admin, r["Hostname"].strip().upper()),
    }


# --------------------------------------------------------------------------- программы

def version_key(v):
    return [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-_ ]", v)]


def match_rule(name):
    """-> (программа или None, версия-режим, дата?, match) или None, если ни одно правило не подошло."""
    for rx, canon, ver_mode, use_date in COMPILED_RULES:
        m = rx.fullmatch(name.strip())
        if m:
            return canon, ver_mode, use_date, m
    return None


def raw_key(name):
    """Ключ для пользовательских сопоставлений: название без номеров версий и пометок разрядности."""
    s = name.lower().strip()
    s = re.sub(r",\s*версия\s+\S+$", "", s)
    s = re.sub(r"\((x64|x86|64-bit|32-bit|64 бита|32 бита|64-разрядная версия|64-разрядная|x64 ru|"
               r"64-bit x64|only current user|all users|user)\)", " ", s)
    s = re.sub(r"\s-\s[a-z]{2}-[a-z]{2}(\.proof)?$", " ", s)
    s = re.sub(r"\bv?\d+(\.\d+)+[a-z0-9\-_]*", " ", s)
    return " ".join(s.split())


def resolve_version(ver_mode, m, raw_version):
    if ver_mode == NONE:
        return ""
    if ver_mode == NAME:
        return m.group("v") if m and m.groupdict().get("v") else raw_version
    if ver_mode == YEAR:
        year = m.group("year") if m and m.groupdict().get("year") else ""
        if year and raw_version:
            return f"{year} ({raw_version})"
        return year or raw_version
    return raw_version


def collect_software(rows, aliases=None):
    """Строки software_raw.csv -> ({ad_hostname: {программа: {"versions": set, "dates": set}}}, unknown).

    aliases: {raw_key: программа или None} — сопоставления, заданные администратором на сайте.
    unknown: {raw_key: {"name", "publisher", "versions", "hosts"}} — не распознанные названия.
    """
    aliases = aliases or {}
    result, unknown = {}, {}
    for r in rows:
        name, host = r.get("Name", "").strip(), r.get("Hostname", "").strip().upper()
        if not name or not host:
            continue
        key = raw_key(name)
        rule = match_rule(name)
        if key in aliases:
            canon, ver_mode, use_date, m = aliases[key], RAW, True, None
        elif rule:
            canon, ver_mode, use_date, m = rule
        else:
            u = unknown.setdefault(key, {"name": name, "publisher": r.get("Publisher", ""),
                                         "versions": set(), "hosts": set()})
            if r.get("Version"):
                u["versions"].add(r["Version"])
            u["hosts"].add(host)
            continue
        if canon is None:
            continue
        entry = result.setdefault(host, {}).setdefault(canon, {"versions": set(), "dates": set()})
        version = resolve_version(ver_mode, m, r.get("Version", ""))
        if version:
            entry["versions"].add(version)
        install_date = parse_date(r.get("InstallDate", ""))
        if use_date and install_date:
            entry["dates"].add(install_date)
    return result, unknown


def parse_date(value):
    """Дата установки в любом из встречающихся форматов -> ГГГГ-ММ-ДД или ''."""
    value = value.strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y%m%d", "%d.%m.%Y"):
        try:
            return datetime.strptime(value, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return ""


def summarize(entry):
    """Набор версий/дат одной программы на ПК -> (версия, дата) в формате реестра."""
    version = ", ".join(sorted(entry["versions"], key=version_key))
    date = max(entry["dates"]) if entry["dates"] else ""
    return version, date


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


_COLLECTED_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2}))?|(\d{2})\.(\d{2})\.(\d{4})(?: (\d{2}):(\d{2}))?")


def collected_at(value, fallback):
    """CollectedAt из выгрузки (когда данные собраны на самом ПК) -> ГГГГ-ММ-ДД ЧЧ:ММ.
    Нет или не разобрать, или время из будущего (часы ПК врут) — fallback (время импорта)."""
    m = _COLLECTED_RE.search(value or "")
    if not m:
        return fallback
    if m.group(1):
        y, mo, d, h, mi = m.group(1), m.group(2), m.group(3), m.group(4) or "00", m.group(5) or "00"
    else:
        d, mo, y, h, mi = m.group(6), m.group(7), m.group(8), m.group(9) or "00", m.group(10) or "00"
    try:
        t = datetime(int(y), int(mo), int(d), int(h), int(mi))
    except ValueError:
        return fallback
    return fallback if t > datetime.now() + timedelta(hours=1) else t.strftime("%Y-%m-%d %H:%M")


# --------------------------------------------------------------------------- запись в базу

def software_id(conn, name, stats):
    row = conn.execute("SELECT id FROM software WHERE name = ?", (name,)).fetchone()
    if row:
        return row["id"]
    vendor, category, license_type = CATALOG.get(name, ("", "other", "free"))
    stats["software_new"].append(name)
    return conn.execute("INSERT INTO software (name, vendor, category, license_type) VALUES (?, ?, ?, ?)",
                        (name, vendor, category, license_type)).lastrowid


def load_aliases(conn):
    return {r["raw_key"]: r["name"] for r in conn.execute(
        """SELECT a.raw_key, s.name FROM sw_aliases a LEFT JOIN software s ON s.id = a.software_id""")}


def apply_import(conn, computers, software, log_history=True):
    """Записывает выгрузку в базу. Возвращает статистику. Всё в одной транзакции.

    log_history=False — повторный прогон прошлой выгрузки после сопоставления названий: программы там
    не установлены заново, их просто начали узнавать, поэтому в историю ПК это не пишется."""
    at = history.now_str()  # все события одной выгрузки — с одним временем
    stats = {"pcs": 0, "pcs_new": [], "pcs_skipped": [], "pcs_no_software": [], "auditoriums_new": [],
             "added": 0, "updated": 0, "removed": 0, "unchanged": 0, "software_new": [], "unknown": 0}
    if not computers:
        raise InventoryError("В выгрузке нет ни одного компьютера.")

    installs, unknown = collect_software(software, load_aliases(conn))
    sw_rows = {r.get("Hostname", "").strip().upper() for r in software}
    # Когда собран список программ ПК: своё CollectedAt в software_raw.csv, если оно там есть.
    sw_collected = {}
    for r in software:
        host = r.get("Hostname", "").strip().upper()
        if r.get("CollectedAt") and r["CollectedAt"] > sw_collected.get(host, ""):
            sw_collected[host] = r["CollectedAt"]

    try:
        for r in computers:
            pc = normalize_computer(r)
            if not pc:
                stats["pcs_skipped"].append(r.get("Hostname", "?"))
                continue
            stats["pcs"] += 1
            aud = conn.execute("SELECT id FROM auditoriums WHERE num = ?", (pc["aud_num"],)).fetchone()
            if aud:
                aud_id = aud["id"]
            else:
                aud_id = conn.execute("INSERT INTO auditoriums (num) VALUES (?)", (pc["aud_num"],)).lastrowid
                stats["auditoriums_new"].append(f"AUD-{pc['aud_num']}")
            fields = (pc["os"], pc["os_version"], pc["cpu"], pc["ram"], pc["disk"], pc["note"])
            hostname = f"PC-{pc['aud_num']:02d}-{pc['num']:02d}"
            row = conn.execute("SELECT * FROM computers WHERE auditorium_id = ? AND num = ?",
                               (aud_id, pc["num"])).fetchone()
            if row:
                pc_id = row["id"]
                conn.execute("UPDATE computers SET os=?, os_version=?, cpu=?, ram=?, disk=?, note=? WHERE id=?",
                             fields + (pc_id,))
                if log_history:
                    history.log_hw_changes(conn, pc_id, hostname, history.hw_snapshot(row), history.hw_snapshot(pc),
                                           "auto", at=at)
            else:
                pc_id = conn.execute(
                    """INSERT INTO computers (auditorium_id, num, os, os_version, cpu, ram, disk, note)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (aud_id, pc["num"]) + fields).lastrowid
                stats["pcs_new"].append(hostname)
                if log_history:
                    history.log(conn, pc_id, hostname, history.PC_ADDED, source="auto", at=at)

            # Когда ПК последний раз прислал данные — даже если в них ничего не поменялось.
            # Повторный прогон старого архива время не трогает; MAX — чтобы старый архив, загруженный
            # вручную, не «состарил» ПК.
            if log_history:
                hw_at = collected_at(r.get("CollectedAt"), at)
                conn.execute("UPDATE computers SET inv_hw_at = MAX(inv_hw_at, ?) WHERE id = ?", (hw_at, pc_id))
                if pc["ad_hostname"] in sw_rows:
                    sw_at = collected_at(sw_collected.get(pc["ad_hostname"]) or r.get("CollectedAt"), at)
                    conn.execute("UPDATE computers SET inv_sw_at = MAX(inv_sw_at, ?) WHERE id = ?", (sw_at, pc_id))

            # Нет ни одной строки ПО по этому ПК — сбор не удался, список программ не трогаем.
            if pc["ad_hostname"] not in sw_rows:
                stats["pcs_no_software"].append(f"PC-{pc['aud_num']:02d}-{pc['num']:02d}")
                continue

            current, names = {}, {}
            for name, entry in installs.get(pc["ad_hostname"], {}).items():
                sw_id = software_id(conn, name, stats)
                current[sw_id], names[sw_id] = summarize(entry), name
            existing = {r["software_id"]: r for r in conn.execute(
                "SELECT i.*, s.name FROM installations i JOIN software s ON s.id = i.software_id "
                "WHERE i.computer_id = ?", (pc_id,))}
            # Первая выгрузка по ПК: в историю — одна строка «найдено N программ», а не сотни «установлена».
            first = not any(old["source"] == "auto" for old in existing.values())
            added_here = 0
            for sw_id, (version, date) in current.items():
                old = existing.get(sw_id)
                if old is None:
                    conn.execute("""INSERT INTO installations (computer_id, software_id, version, installed_at, source)
                                    VALUES (?, ?, ?, ?, 'auto')""", (pc_id, sw_id, version, date))
                    stats["added"] += 1
                    added_here += 1
                    if log_history and not first:
                        history.log(conn, pc_id, hostname, history.SW_ADDED, names[sw_id], new=version,
                                    source="auto", date=date, software_id=sw_id, at=at)
                else:
                    if (old["version"], old["installed_at"], old["source"]) != (version, date, "auto"):
                        conn.execute("UPDATE installations SET version = ?, installed_at = ?, source = 'auto' "
                                     "WHERE id = ?", (version, date, old["id"]))
                    # Смена только пометки «ручная → авто» изменением не считается.
                    changed = (old["version"], old["installed_at"]) != (version, date)
                    stats["updated" if changed else "unchanged"] += 1
                    # В историю — только смена версии (дата установки сама по себе — не событие).
                    if log_history and old["version"] and version and old["version"] != version:
                        history.log(conn, pc_id, hostname, history.SW_UPDATED, names[sw_id], old["version"], version,
                                    source="auto", date=date, software_id=sw_id, at=at)
            if log_history and first and added_here:
                history.log(conn, pc_id, hostname, history.FIRST_INVENTORY, new=str(added_here), source="auto", at=at)
            # Программа пропала из выгрузки — удаляем, но только записи, созданные импортом.
            for sw_id, old in existing.items():
                if sw_id not in current and old["source"] == "auto":
                    conn.execute("DELETE FROM installations WHERE id = ?", (old["id"],))
                    stats["removed"] += 1
                    if log_history:
                        history.log(conn, pc_id, hostname, history.SW_REMOVED, old["name"], old=old["version"],
                                    source="auto", software_id=sw_id, at=at)

        conn.execute("DELETE FROM import_unknown")
        conn.executemany(
            "INSERT INTO import_unknown (raw_key, name, publisher, versions, hosts) VALUES (?, ?, ?, ?, ?)",
            [(k, u["name"], u["publisher"], ", ".join(sorted(u["versions"], key=version_key)),
              ", ".join(sorted(u["hosts"]))) for k, u in unknown.items()])
        stats["unknown"] = len(unknown)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return stats


def run_import(conn, data, origin, filename=""):
    """Полный цикл: чтение архива, запись, журнал. Возвращает (ok, сообщение, статистика)."""
    try:
        computers, software = read_archive(data)
        stats = apply_import(conn, computers, software, log_history=origin != "rerun")
        ok, message = True, format_stats(stats)
    except InventoryError as e:
        ok, message, stats = False, str(e), {}
    except Exception as e:  # noqa: BLE001 — любую ошибку записываем в журнал, база откатывается
        ok, message, stats = False, f"Ошибка импорта: {e.__class__.__name__}: {e}", {}
    conn.execute("INSERT INTO imports (created_at, origin, filename, ok, message, stats) VALUES (?, ?, ?, ?, ?, ?)",
                 (now_str(), origin, filename, int(ok), message, json.dumps(stats, ensure_ascii=False)))
    conn.execute("DELETE FROM imports WHERE id NOT IN (SELECT id FROM imports ORDER BY id DESC LIMIT 200)")
    conn.commit()
    return ok, message, stats


def short_list(items, limit=10):
    items = sorted(set(items), key=str.lower)
    head = ", ".join(items[:limit])
    return head + (f" и ещё {len(items) - limit}" if len(items) > limit else "")


def format_stats(s):
    parts = [f"ПК: {s['pcs']}", f"добавлено программ: {s['added']}", f"изменено: {s['updated']}",
             f"удалено: {s['removed']}"]
    if s["pcs_new"]:
        parts.append(f"новые ПК: {short_list(s['pcs_new'])}")
    if s["auditoriums_new"]:
        parts.append(f"новые аудитории: {short_list(s['auditoriums_new'])}")
    if s["software_new"]:
        parts.append(f"новые программы в справочнике: {short_list(s['software_new'])}")
    if s["pcs_no_software"]:
        parts.append(f"без списка ПО (не тронуты): {short_list(s['pcs_no_software'])}")
    if s["pcs_skipped"]:
        parts.append(f"пропущены (имя не по схеме): {short_list(s['pcs_skipped'])}")
    if s["unknown"]:
        parts.append(f"нераспознанных названий: {s['unknown']}")
    return "; ".join(parts)
