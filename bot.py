import asyncio
import io
import itertools
import logging
import os
from collections import OrderedDict
from html import escape

from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandObject
from aiogram.types import BotCommand, BufferedInputFile, CallbackQuery, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder
from dotenv import load_dotenv

import checker
import module as m

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
OWNER_ID = int(os.getenv("OWNER_ID") or 0)
REGION = (os.getenv("DEFAULT_REGION") or "ET").upper()
if not TOKEN or not OWNER_ID:
    raise SystemExit("Set BOT_TOKEN and OWNER_ID in your .env file")

logging.basicConfig(level=logging.INFO)
dp = Dispatcher()
dp.message.filter(F.from_user.id == OWNER_ID)  # only you can use the bot
dp.callback_query.filter(F.from_user.id == OWNER_ID)

# kind -> (icon, title, async function)
KINDS = {
    "user": ("👤", "Username scan", m.username),
    "email": ("📧", "Email scan", m.email),
    "breach": ("💥", "Breach check", m.breach),
    "phone": ("📱", "Phone lookup", lambda t: m.phone(t, REGION)),
    "name": ("🧑", "Name search", m.name_search),
    "domain": ("🌐", "Domain recon", m.domain),
    "ip": ("📡", "IP intel", m.ip_lookup),
    "tg": ("✈️", "Telegram lookup", m.telegram),
    "dork": ("🕵️", "Dork builder", m.dorks),
}

# short ids for inline buttons (callback data is limited to 64 bytes)
PENDING: OrderedDict[str, tuple[str, str]] = OrderedDict()
_ids = itertools.count(1)


def stash(kind: str, target: str) -> str:
    key = str(next(_ids))
    PENDING[key] = (kind, target)
    while len(PENDING) > 500:
        PENDING.popitem(last=False)
    return key


def chunk(text: str, limit: int = 3800) -> list[str]:
    """Split on blank-line blocks so HTML tags / blockquotes are never cut in half."""
    units = []
    for block in text.split("\n\n"):
        if len(block) <= limit:
            units.append((block, "\n\n"))
        else:
            units.extend((ln, "\n") for ln in block.split("\n"))
    parts, cur = [], ""
    for unit, sep in units:
        if cur and len(cur) + len(sep) + len(unit) > limit:
            parts.append(cur)
            cur = unit
        else:
            cur = cur + sep + unit if cur else unit
    if cur:
        parts.append(cur)
    return parts


def keyboard(res: m.Result):
    kb = InlineKeyboardBuilder()
    for label, url in res.links:
        kb.button(text=label, url=url)
    for label, kind, target in res.actions:
        kb.button(text=label, callback_data="r:" + stash(kind, target))
    if not (res.links or res.actions):
        return None
    kb.adjust(2)
    return kb.as_markup()


async def deliver(status: Message, origin: Message, res: m.Result):
    parts = chunk(res.text)
    kb = keyboard(res)
    for i, part in enumerate(parts):
        markup = kb if i == len(parts) - 1 else None
        if i == 0:
            await status.edit_text(part, reply_markup=markup)
        else:
            await origin.answer(part, reply_markup=markup)
    if res.file:
        name, data = res.file
        await origin.answer_document(BufferedInputFile(data, filename=name), caption="📄 Full list")


async def execute(kind: str, target: str, origin: Message):
    icon, title, fn = KINDS[kind]
    status = await origin.answer(f"{icon} <b>{title}</b>\n<code>{escape(target)}</code>\n⏳ Working...")
    try:
        res = await asyncio.wait_for(fn(target), timeout=240)
        await deliver(status, origin, res)
    except asyncio.TimeoutError:
        await status.edit_text(f"{icon} <b>{title}</b>\n⏱ Took too long - try again.")
    except Exception as ex:
        logging.exception("%s failed", kind)
        await status.edit_text(f"{icon} <b>{title}</b>\n⚠️ Failed: <code>{escape(str(ex)[:200])}</code>")


# ───────────── smart mode: detect what was sent ─────────────
def plan_for(kind: str, text: str) -> list[tuple[str, str, str]]:
    t = text.strip()
    if kind == "email":
        plan = [("📧 Full email scan", "email", t), ("💥 Breaches only", "breach", t)]
        local = t.split("@")[0]
        if checker.USERNAME_RE.match(local):
            plan.append((f"👤 Scan “{local[:18]}”", "user", local))
    elif kind == "phone":
        plan = [("📱 Phone lookup", "phone", t)]
    elif kind == "username":
        u = t.lstrip("@")
        plan = [("👤 Username scan", "user", u), ("✈️ Telegram", "tg", u)]
    elif kind == "domain":
        plan = [("🌐 Domain recon", "domain", t)]
    elif kind == "ip":
        plan = [("📡 IP intel", "ip", t)]
    elif kind == "tg":
        u = m.TG_RE.match(t).group(1)
        plan = [("✈️ Telegram lookup", "tg", t), ("👤 Username scan", "user", u)]
    else:
        plan = [("🧑 Name search", "name", t)]
    plan.append(("🕵️ Dorks", "dork", t))
    return plan


async def smart(message: Message, text: str):
    kind = m.detect(text)
    plan = plan_for(kind, text)
    kb = InlineKeyboardBuilder()
    for label, k, target in plan:
        kb.button(text=label, callback_data="r:" + stash(k, target))
    kb.button(text="⚡ Run everything", callback_data="r:" + stash("all", text.strip()))
    kb.adjust(2)
    await message.answer(
        f"🎯 Detected <b>{kind}</b>\n<code>{escape(text.strip()[:120])}</code>\n\nPick a scan:",
        reply_markup=kb.as_markup(),
    )


@dp.callback_query(F.data.startswith("r:"))
async def on_button(cb: CallbackQuery):
    item = PENDING.get(cb.data[2:])
    if not item:
        await cb.answer("Expired - send the target again", show_alert=True)
        return
    await cb.answer()
    kind, target = item
    if kind == "all":
        for _, k, t in plan_for(m.detect(target), target):
            await execute(k, t, cb.message)
    else:
        await execute(kind, target, cb.message)


# ───────────── commands ─────────────
START = (
    "🕵️ <b>OSINT Toolkit</b>\n"
    "Send me anything - I'll detect what it is.\n\n"
    "👤 /user - username on 690+ sites\n"
    "📧 /email - mail server, Gravatar, 100+ services, breaches\n"
    "💥 /breach - leaked-data check\n"
    "📱 /phone - country, carrier, line type, quick links\n"
    "🧑 /name - name → username guesses + dorks\n"
    "🌐 /domain - WHOIS, DNS, subdomains\n"
    "📡 /ip - location, ISP, open ports\n"
    "✈️ /tg - public Telegram profile\n"
    "🕵️ /dork - ready-made Google dorks\n\n"
    "📷 Send a photo → reverse-search links\n"
    "🗂 Send an image as File → EXIF + GPS\n"
    "↪️ Forward a message → sender ID\n\n"
    "⚠️ Public data only. Use on yourself or with permission."
)


@dp.message(Command("start", "help"))
async def cmd_start(message: Message):
    await message.answer(START)


COMMANDS = [
    ("user", "user", "username"),
    ("email", "email", "name@mail.com"),
    ("breach", "breach", "name@mail.com"),
    ("phone", "phone", "+251911234567"),
    ("name", "name", "Full Name"),
    ("domain", "domain", "example.com"),
    ("ip", "ip", "8.8.8.8"),
    ("tg", "tg", "@username"),
    ("dork", "dork", "anything"),
]


def register(cmd: str, kind: str, usage: str):
    @dp.message(Command(cmd))
    async def handler(message: Message, command: CommandObject):
        arg = (command.args or "").strip()
        if not arg:
            await message.answer(f"Usage: <code>/{cmd} {escape(usage)}</code>")
            return
        await execute(kind, arg, message)


for _cmd in COMMANDS:
    register(*_cmd)


@dp.message(Command("scan"))
async def cmd_scan(message: Message, command: CommandObject):
    arg = (command.args or "").strip()
    if not arg:
        await message.answer("Usage: <code>/scan anything</code>")
        return
    await smart(message, arg)


# ───────────── forwarded messages, photos, files ─────────────
@dp.message(F.forward_origin)
async def on_forward(message: Message):
    fo = message.forward_origin
    out = m.head("↪️", "Forward Origin")
    res = None
    if fo.type == "user":
        u = fo.sender_user
        out += m.row("Type", "User" + (" (bot)" if u.is_bot else ""))
        out += m.row("ID", u.id)
        out += m.row("Name", u.full_name)
        out += m.row("Username", f"@{u.username}" if u.username else "")
        res = m.Result(out, links=[("👤 Open profile", f"tg://user?id={u.id}")],
                       actions=[("✈️ Telegram lookup", "tg", u.username)] if u.username else [])
    elif fo.type == "hidden_user":
        out += m.row("Type", "User with hidden forwards")
        out += m.row("Name shown", fo.sender_user_name)
        out += "\n<i>This user's privacy settings hide their ID.</i>"
        res = m.Result(out)
    elif fo.type in ("chat", "channel"):
        c = fo.sender_chat if fo.type == "chat" else fo.chat
        out += m.row("Type", c.type.capitalize())
        out += m.row("ID", c.id)
        out += m.row("Title", c.title)
        out += m.row("Username", f"@{c.username}" if c.username else "")
        res = m.Result(out, actions=[("✈️ Telegram lookup", "tg", c.username)] if c.username else [])
    else:
        res = m.Result(out + m.row("Type", fo.type))
    status = await message.answer("↪️ Reading forward...")
    await deliver(status, message, res)


@dp.message(F.photo)
async def on_photo(message: Message):
    status = await message.answer("📷 ...")
    await deliver(status, message, m.photo_tip())


@dp.message(F.document)
async def on_document(message: Message):
    doc = message.document
    if not (doc.mime_type or "").startswith("image/"):
        await message.answer("Send an <b>image</b> as a file to read its EXIF data.")
        return
    if doc.file_size and doc.file_size > 20 * 1024 * 1024:
        await message.answer("That file is over 20 MB - Telegram bots can't download it.")
        return
    status = await message.answer("📷 Reading EXIF...")
    buf = io.BytesIO()
    await message.bot.download(doc, destination=buf)
    await deliver(status, message, m.exif_report(buf.getvalue()))


# plain text (registered last so commands and forwards win)
@dp.message(F.text & ~F.text.startswith("/"))
async def on_text(message: Message):
    await smart(message, message.text)


async def main():
    bot = Bot(
        TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML, link_preview_is_disabled=True),
    )
    await bot.set_my_commands([
        BotCommand(command="user", description="Username scan (690+ sites)"),
        BotCommand(command="email", description="Email scan + breaches"),
        BotCommand(command="phone", description="Phone number lookup"),
        BotCommand(command="name", description="Name search + username guesses"),
        BotCommand(command="domain", description="WHOIS, DNS, subdomains"),
        BotCommand(command="ip", description="IP location + open ports"),
        BotCommand(command="tg", description="Public Telegram profile"),
        BotCommand(command="breach", description="Breach check"),
        BotCommand(command="dork", description="Google dork builder"),
        BotCommand(command="scan", description="Auto-detect anything"),
        BotCommand(command="help", description="Show all features"),
    ])
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())