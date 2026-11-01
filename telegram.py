"""Уведомления администратору в Telegram через бота (Bot API, без сторонних библиотек)."""
import json
import logging
import threading
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.telegram.org/bot{token}/{method}"
TIMEOUT = 10
log = logging.getLogger(__name__)


def call(token, method, **params):
    """Вызов метода Bot API. Возвращает result или бросает RuntimeError с понятным текстом."""
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(API.format(token=token, method=method), data=data)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            payload = json.load(e)
        except ValueError:
            raise RuntimeError(f"HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"нет связи с api.telegram.org: {getattr(e, 'reason', e)}") from None
    if not payload.get("ok"):
        desc = payload.get("description", "неизвестная ошибка")
        hints = {"Unauthorized": "неверный токен бота",
                 "Bad Request: chat not found": "chat id не найден — напишите боту и нажмите «Найти chat id»"}
        raise RuntimeError(hints.get(desc, desc))
    return payload["result"]


def send(token, chat_id, text):
    call(token, "sendMessage", chat_id=chat_id, text=text, parse_mode="HTML",
         disable_web_page_preview="true")


def send_async(token, chat_id, text):
    """Отправка в фоне, чтобы страница не ждала Telegram. Ошибки — только в журнал."""
    def run():
        try:
            send(token, chat_id, text)
        except RuntimeError as e:
            log.warning("telegram: не удалось отправить: %s", e)
    threading.Thread(target=run, daemon=True).start()


def recent_chats(token):
    """Чаты, из которых недавно писали боту: [(chat_id, название)]."""
    chats = {}
    for upd in call(token, "getUpdates", limit=50):
        msg = upd.get("message") or upd.get("my_chat_member") or upd.get("channel_post") or {}
        chat = msg.get("chat")
        if chat:
            title = chat.get("title") or " ".join(
                filter(None, [chat.get("first_name"), chat.get("last_name")])) or chat.get("username", "")
            chats[chat["id"]] = f"{title} ({chat.get('type', '')})"
    return list(chats.items())
