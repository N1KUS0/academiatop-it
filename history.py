"""История изменений на ПК: что и когда установлено или удалено, что поменялось в «железе».

События пишут и автовыгрузка (inventory.py), и ручные правки на сайте. IP и MAC не отслеживаются:
адреса меняются сами (DHCP, VPN, виртуальные адаптеры), это не изменения компьютера.
"""
import re
from datetime import datetime

import netmap

# Виды событий
SW_ADDED = "sw_added"        # программа появилась на ПК
SW_REMOVED = "sw_removed"    # программа пропала с ПК
SW_UPDATED = "sw_updated"    # сменилась версия
HW = "hw"                    # поменялось «железо» или ОС: field — что именно
PC_ADDED = "pc_added"        # ПК появился в реестре
PC_RENAMED = "pc_renamed"    # ПК перенесли в другую аудиторию или сменили номер
PC_REMOVED = "pc_removed"    # ПК удалили из реестра
PC_STATUS = "pc_status"      # сменился статус: в работе / в ремонте / списан
FIRST_INVENTORY = "first"    # первая автовыгрузка по ПК: сколько программ найдено (без списка — иначе сотни строк)

# Что считается «железом» (и ОС): поле -> подпись. Версия ОС — без номера сборки, иначе событие каждый месяц.
HW_FIELDS = {"cpu": "Процессор", "ram": "ОЗУ", "disk": "Диски", "board": "Плата", "os": "ОС", "os_version": "Версия ОС"}

KIND_GROUPS = {"sw": (SW_ADDED, SW_REMOVED, FIRST_INVENTORY), "updates": (SW_UPDATED,),
               "hw": (HW,), "pc": (PC_ADDED, PC_RENAMED, PC_REMOVED, PC_STATUS)}

_BUILD_RE = re.compile(r"\s*\([\d.]+\)\s*$")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def hw_snapshot(pc):
    """Поля «железа» ПК (строка базы или dict) -> {поле: значение} для сравнения."""
    return {"cpu": pc["cpu"] or "", "ram": pc["ram"] or "", "disk": pc["disk"] or "",
            "board": netmap.note_field(pc["note"], "Плата").strip(),
            "os": pc["os"] or "", "os_version": _BUILD_RE.sub("", pc["os_version"] or "")}


def log(conn, computer_id, hostname, kind, field="", old="", new="", source="manual", who="", date="",
        software_id=None, at=None):
    conn.execute(
        """INSERT INTO pc_history (computer_id, hostname, at, kind, field, old, new, date, software_id, source, who)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (computer_id, hostname, at or now_str(), kind, field, old or "", new or "", date or "", software_id,
         source, who or ""))


def log_hw_changes(conn, computer_id, hostname, before, after, source="manual", who="", at=None):
    """Записать изменения «железа» между двумя снимками. Пустое старое значение — это первое заполнение,
    а не изменение (иначе первая выгрузка даст по шесть событий на каждый ПК); пустое новое — сборщик
    не смог прочитать поле, это тоже не замена «железа». Такие случаи не пишем."""
    for field in HW_FIELDS:
        old, new = before.get(field, ""), after.get(field, "")
        if old and new and old != new:
            log(conn, computer_id, hostname, HW, field, old, new, source, who, at=at)
