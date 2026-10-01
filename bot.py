import asyncio
import logging
import os
import time
from collections import defaultdict
from html import escape

from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandObject
from aiogram.types import Message
from dotenv import load_dotenv

import checker

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
OWNER_ID = int(os.getenv("OWNER_ID") or 0)
if not TOKEN or not OWNER_ID:
    raise SystemExit("Set BOT_TOKEN and OWNER_ID in your .env file")

logging.basicConfig(level=logging.INFO)
dp = Dispatcher()
dp.message.filter(F.from_user.id == OWNER_ID)  # only you can use the bot


def chunk(text: str, limit: int = 3900) -> list[str]:
    parts, cur = [], ""
    for line in text.split("\n"):
        if len(cur) + len(line) + 1 > limit:
            parts.append(cur)
            cur = ""
        cur += line + "\n"
    if cur.strip():
        parts.append(cur)
    return parts


@dp.message(Command("start", "help"))
async def cmd_start(message: Message):
    await message.answer(
        "<b>OSINT Bot</b>\n\n"
        "/user <code>&lt;username&gt;</code> - scan 700+ sites for a username"
    )


@dp.message(Command("user"))
async def cmd_user(message: Message, command: CommandObject):
    username = (command.args or "").strip().lstrip("@")
    if not checker.USERNAME_RE.match(username):
        await message.answer("Usage: /user <code>username</code>\nAllowed: letters, numbers, . _ -")
        return

    status = await message.answer(f"Scanning <b>{escape(username)}</b> ...")
    t0 = time.time()
    try:
        hits, total = await checker.scan(username)
    except Exception as e:
        logging.exception("scan failed")
        await status.edit_text(f"Scan failed: <code>{escape(str(e))}</code>")
        return

    elapsed = time.time() - t0
    if not hits:
        await status.edit_text(f"No hits for <b>{escape(username)}</b> ({total} sites, {elapsed:.0f}s)")
        return

    by_cat = defaultdict(list)
    for h in hits:
        by_cat[h["cat"]].append(h)

    lines = [f"<b>{escape(username)}</b> - {len(hits)} hits / {total} sites ({elapsed:.0f}s)\n"]
    for cat, items in by_cat.items():
        lines.append(f"\n<b>{escape(cat.upper())}</b>")
        for h in items:
            lines.append(f'• <a href="{escape(h["url"], quote=True)}">{escape(h["site"])}</a>')

    parts = chunk("\n".join(lines))
    await status.edit_text(parts[0])
    for p in parts[1:]:
        await message.answer(p)


async def main():
    bot = Bot(
        TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML, link_preview_is_disabled=True),
    )
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())