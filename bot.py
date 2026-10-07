import asyncio
import itertools
import logging
import os
from collections import OrderedDict
from html import escape

import aiohttp
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandObject
from aiogram.types import (BotCommand, BufferedInputFile, CallbackQuery, KeyboardButton,
                           Message, ReplyKeyboardMarkup)
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiohttp import web
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

# ───────────── bottom menu (buttons under the text field) ─────────────
TOOL_BUTTONS = {
    "👤 Username": "user", "📧 Email": "email", "📱 Phone": "phone",
    "🧑 Name": "name", "🌐 Domain": "domain", "📡 IP": "ip",
    "✈️ Telegram": "tg", "💥 Breach": "breach", "🕵️ Dorks": "dork",
}
BTN_IMAGE, BTN_AUTO, BTN_HELP = "🖼 Image", "⚡ Auto", "❓ Help"
MENU_ROWS = [
    ["👤 Username", "📧 Email", "📱 Phone"],
    ["🧑 Name", "🌐 Domain", "📡 IP"],
    ["✈️ Telegram", "💥 Breach", "🕵️ Dorks"],
    [BTN_IMAGE, BTN_AUTO, BTN_HELP],
]


def norm(s: str) -> str:
    return (s or "").replace("\ufe0f", "").strip()


NORM_TOOLS = {norm(k): v for k, v in TOOL_BUTTONS.items()}


def main_menu() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=t) for t in row] for row in MENU_ROWS],
        resize_keyboard=True,
        is_persistent=True,
        input_field_placeholder="Tap a tool, or just send anything...",
    )


# what each tool asks for: (what to send, example, how long)
PROMPTS = {
    "user": ("a username", "abelxeon", "20-60 sec"),
    "email": ("an email address", "name@gmail.com", "1-2 min"),
    "phone": ("a phone number", "+251911234567", "instant"),
    "name": ("a full name", "Abel Tiruneh", "instant"),
    "domain": ("a domain", "example.com", "10-30 sec"),
    "ip": ("an IP address", "8.8.8.8", "3-5 sec"),
    "tg": ("a Telegram @username or t.me link", "@durov", "2-3 sec"),
    "breach": ("an email address", "name@gmail.com", "5-10 sec"),
    "dork": ("anything (name, email, phone, username)", "abelxeon", "instant"),
}

MODE: dict[int, str] = {}  # user id -> tool waiting for input

# ───────────── helpers ─────────────
PENDING: OrderedDict[str, tuple[str, str]] = OrderedDict()  # short ids for inline buttons
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
    status = await origin.answer(f"{icon} <b>{title.upper()}</b>\n<code>{escape(target)}</code>\n⏳ Working...")
    try:
        res = await asyncio.wait_for(fn(target), timeout=240)
        await deliver(status, origin, res)
    except asyncio.TimeoutError:
        await status.edit_text(f"{icon} <b>{title.upper()}</b>\n⏱ Took too long - try again.")
    except Exception as ex:
        logging.exception("%s failed", kind)
        await status.edit_text(f"{icon} <b>{title.upper()}</b>\n⚠️ Failed: <code>{escape(str(ex)[:200])}</code>")


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
        f"🎯 <b>DETECTED: {kind.upper()}</b>\n<code>{escape(text.strip()[:120])}</code>\n\nPick a scan:",
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


# ───────────── help center ─────────────
WELCOME = (
    "🕵️ <b>OSINT TOOLKIT</b>\n"
    "━━━━━━━━━━━━━━━━━━\n"
    "Find public information about a username, email, phone, name, domain, IP or Telegram account.\n\n"
    "<b>How to use</b>\n"
    "├ 1️⃣ Tap a tool in the menu below\n"
    "├ 2️⃣ Send the target\n"
    "└ 3️⃣ Get a clean report with quick-open buttons\n\n"
    "💡 Or skip the menu: just send anything and I'll detect what it is.\n"
    "📷 Send a photo to reverse-search it, or an image as <b>File</b> to read its EXIF/GPS.\n"
    "↪️ Forward a message to see who sent it.\n\n"
    "❓ Tap <b>Help</b> for a guide to every tool.\n\n"
    "⚠️ <i>Public data only. Use on yourself or with permission.</i>"
)

HELP_HOME = (
    "❓ <b>HELP CENTER</b>\n"
    "━━━━━━━━━━━━━━━━━━\n"
    "Tap the menu button of a tool, send the target, and wait for the report.\n\n"
    "Pick a topic to see how it works, an example, and how long it takes:"
)

HELP_TOPICS = {
    "user": ("👤 Username",
             "👤 <b>USERNAME SCAN</b>\n━━━━━━━━━━━━━━━━━━\n"
             "<b>What it does</b>\nChecks one username on about 690 websites at the same time and lists only the sites where that profile exists.\n\n"
             "<b>Example</b>  <code>abelxeon</code>\n<b>Time</b>  20-60 seconds\n\n"
             "<b>Good to know</b>\n├ Results are grouped by type (social, coding, gaming...)\n"
             "├ A full list is also sent as a .txt file\n"
             "└ Common usernames match many different people - open the link to confirm"),
    "email": ("📧 Email",
              "📧 <b>EMAIL SCAN</b>\n━━━━━━━━━━━━━━━━━━\n"
              "<b>What it does</b>\nChecks the mail server, a public Gravatar profile, 100+ websites where the email is registered, and known data breaches.\n\n"
              "<b>Example</b>  <code>name@gmail.com</code>\n<b>Time</b>  1-2 minutes\n\n"
              "<b>Good to know</b>\n├ It never sends an email to the person\n"
              "├ \"Registered on\" shows accounts that use this email\n"
              "└ Tap the 👤 button to scan the part before @ as a username"),
    "phone": ("📱 Phone",
              "📱 <b>PHONE LOOKUP</b>\n━━━━━━━━━━━━━━━━━━\n"
              "<b>What it does</b>\nReads the number and shows if it is valid, the country, region, carrier, line type and timezone. Adds buttons to open WhatsApp, Telegram, Truecaller and Google.\n\n"
              "<b>Example</b>  <code>+251911234567</code>\n<b>Time</b>  instant\n\n"
              "<b>Good to know</b>\n├ Always better with the + country code\n"
              "├ Carrier is the original operator (ported numbers can differ)\n"
              "└ It cannot tell you the owner's name"),
    "name": ("🧑 Name",
             "🧑 <b>NAME SEARCH</b>\n━━━━━━━━━━━━━━━━━━\n"
             "<b>What it does</b>\nTurns a full name into likely usernames and opens ready-made searches on Google, LinkedIn, Facebook, Instagram, X, GitHub and Telegram.\n\n"
             "<b>Example</b>  <code>Abel Tiruneh</code>\n<b>Time</b>  instant\n\n"
             "<b>Good to know</b>\n├ Tap a 👤 button to scan a guessed username\n"
             "└ Names are common - confirm with a photo, city or workplace"),
    "domain": ("🌐 Domain",
               "🌐 <b>DOMAIN RECON</b>\n━━━━━━━━━━━━━━━━━━\n"
               "<b>What it does</b>\nShows WHOIS (registrar, dates), DNS records, email security (SPF/DMARC) and subdomains found in certificate logs.\n\n"
               "<b>Example</b>  <code>example.com</code>\n<b>Time</b>  10-30 seconds\n\n"
               "<b>Good to know</b>\n├ Long subdomain lists come as a .txt file\n"
               "└ Many domains hide WHOIS details for privacy"),
    "ip": ("📡 IP",
           "📡 <b>IP INTEL</b>\n━━━━━━━━━━━━━━━━━━\n"
           "<b>What it does</b>\nShows the approximate location, ISP, network, VPN/hosting flags and open ports of a public IP address.\n\n"
           "<b>Example</b>  <code>8.8.8.8</code>\n<b>Time</b>  3-5 seconds\n\n"
           "<b>Good to know</b>\n├ Location is usually the ISP's hub, not a house\n"
           "└ Private IPs (192.168.x.x) have no public data"),
    "tg": ("✈️ Telegram",
           "✈️ <b>TELEGRAM LOOKUP</b>\n━━━━━━━━━━━━━━━━━━\n"
           "<b>What it does</b>\nReads the public t.me page of a username: name, bio, type (user, bot, channel) and profile photo.\n\n"
           "<b>Example</b>  <code>@durov</code>\n<b>Time</b>  2-3 seconds\n\n"
           "<b>Good to know</b>\n├ Only public information is shown\n"
           "└ A numeric ID can't be looked up from the web"),
    "breach": ("💥 Breach",
               "💥 <b>BREACH CHECK</b>\n━━━━━━━━━━━━━━━━━━\n"
               "<b>What it does</b>\nChecks if an email appeared in known data leaks and shows the names of the breached services.\n\n"
               "<b>Example</b>  <code>name@gmail.com</code>\n<b>Time</b>  5-10 seconds\n\n"
               "<b>Good to know</b>\n├ It shows which leaks, never passwords\n"
               "└ If the service is busy, try again in a minute"),
    "dork": ("🕵️ Dorks",
             "🕵️ <b>DORK BUILDER</b>\n━━━━━━━━━━━━━━━━━━\n"
             "<b>What it does</b>\nBuilds advanced Google searches (Pastebin, GitHub, Telegram, documents, leaks) for any text and opens them with one tap.\n\n"
             "<b>Example</b>  <code>abelxeon</code>\n<b>Time</b>  instant"),
    "image": ("📷 Image",
              "📷 <b>IMAGE TOOLS</b>\n━━━━━━━━━━━━━━━━━━\n"
              "<b>Send as Photo</b>\nGives you reverse-search buttons (Google Lens, Yandex, TinEye, Bing).\n\n"
              "<b>Send as File</b>  (📎 → File)\nReads the hidden EXIF data: camera, date taken and GPS location with a map button.\n\n"
              "<b>Time</b>  2-5 seconds\n\n"
              "<b>Good to know</b>\n├ Telegram strips EXIF from normal photos, so use File\n"
              "└ WhatsApp, Instagram and Facebook remove EXIF too"),
    "fwd": ("↪️ Forward",
            "↪️ <b>FORWARD INSPECTOR</b>\n━━━━━━━━━━━━━━━━━━\n"
            "<b>What it does</b>\nForward me any message and I show the sender's ID, name and username (or channel/group info).\n\n"
            "<b>Good to know</b>\n└ If the person hides forwards in privacy settings, the ID stays hidden"),
    "limits": ("⚠️ Limits",
               "⚠️ <b>LIMITS &amp; FAIR USE</b>\n━━━━━━━━━━━━━━━━━━\n"
               "├ Only <b>public</b> data is used\n"
               "├ Results are leads, not proof - always confirm\n"
               "├ Free services can be slow or rate-limited\n"
               "├ Only you (the owner) can use this bot\n"
               "└ Use it on yourself or with the person's permission"),
}


def help_home_kb():
    kb = InlineKeyboardBuilder()
    for key, (label, _) in HELP_TOPICS.items():
        kb.button(text=label, callback_data=f"h:{key}")
    kb.adjust(2)
    return kb.as_markup()


def help_back_kb():
    kb = InlineKeyboardBuilder()
    kb.button(text="⬅️ Back to Help", callback_data="h:home")
    return kb.as_markup()


async def show_help(message: Message):
    await message.answer(HELP_HOME, reply_markup=help_home_kb())


@dp.callback_query(F.data.startswith("h:"))
async def on_help(cb: CallbackQuery):
    key = cb.data[2:]
    text, kb = (HELP_HOME, help_home_kb()) if key == "home" else (
        (HELP_TOPICS[key][1], help_back_kb()) if key in HELP_TOPICS else (None, None))
    await cb.answer()
    if not text:
        return
    try:
        await cb.message.edit_text(text, reply_markup=kb)
    except Exception:
        pass  


@dp.callback_query(F.data == "c:x")
async def on_cancel(cb: CallbackQuery):
    MODE.pop(cb.from_user.id, None)
    await cb.answer("Cancelled")
    try:
        await cb.message.edit_text("✖️ Cancelled.")
    except Exception:
        pass


# ───────────── menu buttons ─────────────
@dp.message(Command("start"))
async def cmd_start(message: Message):
    MODE.pop(message.from_user.id, None)
    await message.answer(WELCOME, reply_markup=main_menu())


@dp.message(Command("help"))
async def cmd_help(message: Message):
    await show_help(message)


@dp.message(F.text.func(lambda t: norm(t) in NORM_TOOLS))
async def on_tool_button(message: Message):
    kind = NORM_TOOLS[norm(message.text)]
    MODE[message.from_user.id] = kind
    icon, title, _ = KINDS[kind]
    what, example, eta = PROMPTS[kind]
    kb = InlineKeyboardBuilder()
    kb.button(text="✖️ Cancel", callback_data="c:x")
    await message.answer(
        f"{icon} <b>{title.upper()}</b>\n━━━━━━━━━━━━━━━━━━\n"
        f"Send me {what}.\n\n"
        f"├ <b>Example</b>  <code>{escape(example)}</code>\n"
        f"└ <b>Time</b>  {eta}",
        reply_markup=kb.as_markup(),
    )


@dp.message(F.text.func(lambda t: norm(t) == norm(BTN_IMAGE)))
async def on_image_button(message: Message):
    MODE.pop(message.from_user.id, None)
    await message.answer(HELP_TOPICS["image"][1])


@dp.message(F.text.func(lambda t: norm(t) == norm(BTN_AUTO)))
async def on_auto_button(message: Message):
    MODE.pop(message.from_user.id, None)
    await message.answer(
        "⚡ <b>AUTO MODE</b>\n━━━━━━━━━━━━━━━━━━\n"
        "Just send anything and I'll detect it:\n"
        "├ an email, phone number, IP or domain\n"
        "├ a username or @telegram link\n"
        "└ a full name\n\n"
        "Then pick a scan - or tap ⚡ <b>Run everything</b>."
    )


@dp.message(F.text.func(lambda t: norm(t) == norm(BTN_HELP)))
async def on_help_button(message: Message):
    MODE.pop(message.from_user.id, None)
    await show_help(message)


# typed commands still work, but you don't need them
def register(cmd: str, kind: str):
    @dp.message(Command(cmd))
    async def handler(message: Message, command: CommandObject):
        arg = (command.args or "").strip()
        if not arg:
            what, example, _ = PROMPTS[kind]
            await message.answer(f"Send {what}, e.g. <code>/{cmd} {escape(example)}</code>")
            return
        await execute(kind, arg, message)


for _cmd, _kind in (("user", "user"), ("email", "email"), ("breach", "breach"), ("phone", "phone"),
                    ("name", "name"), ("domain", "domain"), ("ip", "ip"), ("tg", "tg"), ("dork", "dork")):
    register(_cmd, _kind)


@dp.message(Command("scan"))
async def cmd_scan(message: Message, command: CommandObject):
    arg = (command.args or "").strip()
    if not arg:
        await message.answer("Send anything and I'll detect it.")
        return
    await smart(message, arg)


# ───────────── forwarded messages ─────────────
@dp.message(F.forward_origin)
async def on_forward(message: Message):
    fo = message.forward_origin
    out = m.head("↪️", "Forward Origin")
    actions, links = [], []
    if fo.type == "user":
        u = fo.sender_user
        out += m.tree([("Type", "Bot" if u.is_bot else "User"), ("ID", m.Code(u.id)), ("Name", u.full_name),
                       ("Username", f"@{u.username}" if u.username else "")])
        links = [("👤 Open profile", f"tg://user?id={u.id}")]
        if u.username:
            actions = [("✈️ Telegram lookup", "tg", u.username)]
    elif fo.type == "hidden_user":
        out += m.tree([("Type", "User with hidden forwards"), ("Name shown", fo.sender_user_name)])
        out += "\n<i>This user's privacy settings hide their ID.</i>"
    elif fo.type in ("chat", "channel"):
        c = fo.sender_chat if fo.type == "chat" else fo.chat
        out += m.tree([("Type", c.type.capitalize()), ("ID", m.Code(c.id)), ("Title", c.title),
                       ("Username", f"@{c.username}" if c.username else "")])
        if c.username:
            actions = [("✈️ Telegram lookup", "tg", c.username)]
    else:
        out += m.tree([("Type", fo.type)])
    status = await message.answer("↪️ Reading forward...")
    await deliver(status, message, m.Result(out.rstrip("\n"), links=links, actions=actions))


# ───────────── images (fast EXIF) ─────────────
EXIF_READ_LIMIT = 1_048_576  # EXIF lives at the start of the file, 1 MB is plenty


async def fetch_head(bot: Bot, file_id: str, limit: int = EXIF_READ_LIMIT) -> bytes:
    """Download only the first `limit` bytes of a Telegram file (fast, even for 20 MB originals)."""
    f = await bot.get_file(file_id)
    url = f"https://api.telegram.org/file/bot{TOKEN}/{f.file_path}"
    buf = bytearray()
    timeout = aiohttp.ClientTimeout(total=40, sock_read=15)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        async with s.get(url) as r:
            r.raise_for_status()
            async for part in r.content.iter_chunked(65536):
                buf += part
                if len(buf) >= limit:
                    break
    return bytes(buf)


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
    status = await message.answer("📷 <b>IMAGE EXIF</b>\n⏳ Reading file...")
    try:
        data = await asyncio.wait_for(fetch_head(message.bot, doc.file_id), timeout=45)
    except Exception as ex:
        logging.error("EXIF download failed: %s", type(ex).__name__)
        too_big = "too big" in str(ex).lower()
        await status.edit_text(
            "📷 <b>IMAGE EXIF</b>\n"
            + ("⚠️ Telegram doesn't let bots read files over 20 MB." if too_big
               else "⚠️ Couldn't download the file. Check your connection and send it again."))
        return
    try:
        await deliver(status, message, m.exif_report(data))
    except Exception:
        logging.exception("EXIF report failed")
        await status.edit_text("📷 <b>IMAGE EXIF</b>\n⚠️ Couldn't read this image.")


# ───────────── plain text (last, so buttons and commands win) ─────────────
@dp.message(F.text & ~F.text.startswith("/"))
async def on_text(message: Message):
    kind = MODE.pop(message.from_user.id, None)
    if kind:
        await execute(kind, message.text.strip(), message)
    else:
        await smart(message, message.text)


async def start_health_server():
    """Tiny web server so Render (and UptimeRobot pings) see the service as alive.
    Only starts when Render provides a PORT, so local runs are unchanged."""
    port = int(os.getenv("PORT") or 0)
    if not port:
        return
    app = web.Application()

    async def alive(_request):
        return web.Response(text="OSINT bot is running")

    app.router.add_get("/", alive)
    app.router.add_get("/health", alive)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", port).start()
    logging.info("Health server listening on port %s", port)


async def main():
    await start_health_server()
    bot = Bot(
        TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML, link_preview_is_disabled=True),
    )
    await bot.set_my_commands([
        BotCommand(command="start", description="Open the menu"),
        BotCommand(command="help", description="How everything works"),
    ])
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())