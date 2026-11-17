"""Тексты Telegram в HTML; пользовательские данные экранируются здесь."""
from html import escape
from urllib.parse import urlsplit


def link(url, label):
    try:
        parsed = urlsplit(url or "")
        if parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username:
            return f'<a href="{escape(url, quote=True)}">{escape(label)}</a>'
    except ValueError:
        pass
    return ""


def preview(body):
    return escape(body[:700] + ("…" if len(body) > 700 else ""))


def message(*sections):
    return "\n\n".join(section for section in sections if section)


def admin_ticket(event, ticket, who, body, photos, kind, due, url):
    heading = {"new": "🆕 Новая заявка", "reply": "💬 Ответ сотрудника",
               "reopened": "🔄 Заявка снова открыта", "edit": "✏️ Изменены данные заявки"}[event]
    details = [f"От: {escape(who)}", f"Тип: {escape(kind)}"]
    if ticket["pc_label"]:
        details.append(f"Где: {escape(ticket['pc_label'])}")
    if due:
        details.append(f"Срок: {escape(due)}")
    return message(f"<b>{heading}</b>\n№{ticket['id']} · {escape(ticket['title'])}", "\n".join(details),
                   preview(body), f"📎 Фото: {photos}" if photos else "",
                   link(url, "Открыть заявку →"))


def employee_ticket(ticket, who, body, photos, status, url, own):
    context = "вашей заявке" if own else "заявке, за которой вы следите"
    heading = f"💬 Ответ в {context}" if body or photos else f"🔔 Новый статус в {context}"
    return message(f"<b>{heading}</b>\n№{ticket['id']} · {escape(ticket['title'])}",
                   f"От: <b>{escape(who)}</b>" + (f"\n{preview(body)}" if body else ""),
                   f"📷 Фото в заявке: {photos}" if photos else "",
                   f"Статус: <b>{escape(status)}</b>" if status else "",
                   link(url, "Перейти к переписке →"))


def start(state, site_url):
    texts = {
        "linked": "✅ <b>Готово! Telegram подключён.</b>\nОтветы по вашим заявкам в Академии ТОП будут приходить сюда. Чтобы ответить, перейдите из уведомления в заявку.",
        "already": "🔔 <b>Вы уже на связи!</b>\nЭтот Telegram подключён к порталу. Чтобы использовать его с другим профилем, сначала отключите Telegram в прежнем.",
        "invalid": "⌛ <b>Привязать аккаунт не получилось.</b>\nОткройте свой профиль, получите новую ссылку и нажмите «Старт» ещё раз.",
        "hello": "👋 <b>Здравствуйте! Это бот Академии ТОП.</b>\nХотите получать ответы по заявкам? В своём профиле нажмите «Подключить Telegram», затем откройте бота по личной ссылке.",
    }
    return message(texts[state], link(site_url, "Открыть портал Академии ТОП →"))
