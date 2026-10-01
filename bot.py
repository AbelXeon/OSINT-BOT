import asyncio
import logging
import os
from html import escape

from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandObject
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from dotenv import load_dotenv

import module

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
OWNER_ID = int(os.getenv("OWNER_ID") or 0)

if not TOKEN or not OWNER_ID:
    raise SystemExit("Set BOT_TOKEN and OWNER_ID in your .env file")

logging.basicConfig(level=logging.INFO)
dp = Dispatcher()
# Only you can use the bot
dp.message.filter(F.from_user.id == OWNER_ID)
dp.callback_query.filter(F.from_user.id == OWNER_ID)


def build_keyboard(result: module.Result) -> InlineKeyboardMarkup | None:
    """Builds inline URL buttons and action buttons from a Result."""
    keyboard: list[list[InlineKeyboardButton]] = []

    # Action buttons (internal bot actions)
    action_row = []
    for label, kind, target in result.actions:
        # Keep callback data short to avoid Telegram 64-byte limit
        cb_data = f"act:{kind}:{target[:40]}"
        action_row.append(InlineKeyboardButton(text=label, callback_data=cb_data))
        if len(action_row) == 2:
            keyboard.append(action_row)
            action_row = []
    if action_row:
        keyboard.append(action_row)

    # Link buttons (external web links)
    link_row = []
    for label, url in result.links:
        link_row.append(InlineKeyboardButton(text=label, url=url))
        if len(link_row) == 2:
            keyboard.append(link_row)
            link_row = []
    if link_row:
        keyboard.append(link_row)

    return InlineKeyboardMarkup(inline_keyboard=keyboard) if keyboard else None


async def send_result(message: Message, result: module.Result, status_msg: Message | None = None):
    """Sends text, attaches inline buttons, and sends any generated report file."""
    kb = build_keyboard(result)
    text = result.text.strip()

    # Telegram message character limit safety
    if len(text) > 4000:
        first_part = text[:3900] + "\n\n<i>[Message truncated...]</i>"
        if status_msg:
            await status_msg.edit_text(first_part, reply_markup=kb)
        else:
            await message.answer(first_part, reply_markup=kb)
    else:
        if status_msg:
            await status_msg.edit_text(text, reply_markup=kb)
        else:
            await message.answer(text, reply_markup=kb)

    # If the module produced a report file (like subdomains or username hits)
    if result.file:
        fname, data = result.file
        await message.answer_document(BufferedInputFile(data, filename=fname))


# ──────────────────────── Commands ────────────────────────

@dp.message(Command("start", "help"))
async def cmd_start(message: Message):
    text = (
        "🔍 <b>OSINT Recon Bot</b>\n\n"
        "You can send any input directly, and the bot will <b>auto-detect</b> it:\n"
        "• <code>john_doe</code> → Username scan (700+ sites)\n"
        "• <code>user@example.com</code> → Email intel & breach check\n"
        "• <code>+251911234567</code> → Phone lookup\n"
        "• <code>example.com</code> → Domain DNS, WHOIS & subdomains\n"
        "• <code>8.8.8.8</code> → IP geolocation & Shodan open ports\n"
        "• <code>John Doe</code> → Real name dorking\n"
        "• Send an image as <b>File / Document</b> → EXIF & GPS metadata\n\n"
        "<b>Explicit Commands:</b>\n"
        "/user <code>&lt;username&gt;</code>\n"
        "/email <code>&lt;address&gt;</code>\n"
        "/phone <code>&lt;number&gt;</code>\n"
        "/domain <code>&lt;domain&gt;</code>\n"
        "/ip <code>&lt;ip&gt;</code>\n"
        "/tg <code>&lt;username/id&gt;</code>\n"
        "/dork <code>&lt;query&gt;</code>\n"
        "/breach <code>&lt;email&gt;</code>"
    )
    await message.answer(text)


@dp.message(Command("user"))
async def cmd_user(message: Message, command: CommandObject):
    target = (command.args or "").strip()
    if not target:
        await message.answer("Usage: /user <code>username</code>")
        return
    st = await message.answer(f"⏳ Scanning username <b>{escape(target)}</b> across 700+ sites...")
    res = await module.username(target)
    await send_result(message, res, st)


@dp.message(Command("email"))
async def cmd_email(message: Message, command: CommandObject):
    target = (command.args or "").strip()
    if not target:
        await message.answer("Usage: /email <code>user@example.com</code>")
        return
    st = await message.answer(f"⏳ Checking email <b>{escape(target)}</b>...")
    res = await module.email(target)
    await send_result(message, res, st)


@dp.message(Command("phone"))
async def cmd_phone(message: Message, command: CommandObject):
    target = (command.args or "").strip()
    if not target:
        await message.answer("Usage: /phone <code>+251911234567</code>")
        return
    st = await message.answer("⏳ Processing phone number...")
    res = await module.phone(target)
    await send_result(message, res, st)


@dp.message(Command("domain"))
async def cmd_domain(message: Message, command: CommandObject):
    target = (command.args or "").strip()
    if not target:
        await message.answer("Usage: /domain <code>example.com</code>")
        return
    st = await message.answer(f"⏳ Recon on domain <b>{escape(target)}</b>...")
    res = await module.domain(target)
    await send_result(message, res, st)


@dp.message(Command("ip"))
async def cmd_ip(message: Message, command: CommandObject):
    target = (command.args or "").strip()
    if not target:
        await message.answer("Usage: /ip <code>1.1.1.1</code>")
        return
    st = await message.answer(f"⏳ Querying IP <b>{escape(target)}</b>...")
    res = await module.ip_lookup(target)
    await send_result(message, res, st)


@dp.message(Command("tg"))
async def cmd_tg(message: Message, command: CommandObject):
    target = (command.args or "").strip()
    if not target:
        await message.answer("Usage: /tg <code>username</code>")
        return
    st = await message.answer(f"⏳ Inspecting Telegram target <b>{escape(target)}</b>...")
    res = await module.telegram(target)
    await send_result(message, res, st)


@dp.message(Command("dork"))
async def cmd_dork(message: Message, command: CommandObject):
    target = (command.args or "").strip()
    if not target:
        await message.answer("Usage: /dork <code>query</code>")
        return
    res = await module.dorks(target)
    await send_result(message, res)


@dp.message(Command("breach"))
async def cmd_breach(message: Message, command: CommandObject):
    target = (command.args or "").strip()
    if not target:
        await message.answer("Usage: /breach <code>email@domain.com</code>")
        return
    st = await message.answer(f"⏳ Checking breaches for <b>{escape(target)}</b>...")
    res = await module.breach(target)
    await send_result(message, res, st)


# ──────────────────────── Photos & Documents ────────────────────────

@dp.message(F.photo)
async def handle_photo(message: Message):
    # Telegram strips EXIF from compressed photos
    res = module.photo_tip()
    await send_result(message, res)


@dp.message(F.document)
async def handle_document(message: Message, bot: Bot):
    doc = message.document
    mime = (doc.mime_type or "").lower()
    fname = (doc.file_name or "").lower()

    if "image" in mime or fname.endswith((".jpg", ".jpeg", ".png", ".tiff", ".webp")):
        st = await message.answer("⏳ Analyzing EXIF & GPS metadata...")
        file_io = await bot.download(doc.file_id)
        if file_io:
            data = file_io.read()
            res = module.exif_report(data)
            await send_result(message, res, st)
            return

    await message.answer("❌ Please send an image file (JPG, PNG, etc.) to extract EXIF data.")


# ──────────────────────── Action Callbacks ────────────────────────

@dp.callback_query(F.data.startswith("act:"))
async def handle_action(callback: CallbackQuery):
    await callback.answer("Processing...")
    parts = callback.data.split(":", 2)
    if len(parts) < 3:
        return
    kind, target = parts[1], parts[2]

    msg = callback.message
    if kind == "user":
        st = await msg.reply(f"⏳ Scanning username <b>{escape(target)}</b>...")
        res = await module.username(target)
        await send_result(msg, res, st)
    elif kind == "tg":
        st = await msg.reply(f"⏳ Checking Telegram profile <b>{escape(target)}</b>...")
        res = await module.telegram(target)
        await send_result(msg, res, st)


# ──────────────────────── Auto-Detection ────────────────────────

@dp.message(F.text)
async def handle_any_text(message: Message):
    text = message.text.strip()
    kind = module.detect(text)

    st = await message.answer(f"⏳ Detected <b>{kind.upper()}</b>. Looking up...")
    
    if kind == "email":
        res = await module.email(text)
    elif kind == "ip":
        res = await module.ip_lookup(text)
    elif kind == "tg":
        res = await module.telegram(text)
    elif kind == "phone":
        res = await module.phone(text)
    elif kind == "domain":
        res = await module.domain(text)
    elif kind == "username":
        res = await module.username(text)
    else:  # name
        res = await module.name_search(text)

    await send_result(message, res, st)


# ──────────────────────── Main ────────────────────────

async def main():
    bot = Bot(
        TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML, link_preview_is_disabled=True),
    )
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())