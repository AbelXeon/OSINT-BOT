# 🕵️ OSINT Telegram Bot

A private Telegram bot that gathers **public information** about a username, email, phone number, name, domain, IP address or Telegram account, and returns clean, button-driven reports.

Built with Python, `aiogram 3` and `aiohttp`. Scans 690+ websites at once using asynchronous requests.

> ⚠️ **Use responsibly.** This bot only uses public data. Use it on yourself or with the person's permission. You are responsible for how you use it.

---

## ✨ Features

| Tool | What it does |
|---|---|
| 👤 **Username** | Checks one username on ~690 websites at the same time and lists the profiles that exist, grouped by category. Full list is also sent as a `.txt` file. |
| 📧 **Email** | Mail server (MX) check, public Gravatar profile, 100+ sites where the email is registered ([holehe](https://github.com/megadose/holehe)), and known data breaches. |
| 💥 **Breach** | Shows which known data leaks an email appeared in (never passwords). |
| 📱 **Phone** | Validity, country, region, carrier, line type, timezone, plus quick links to WhatsApp, Telegram, Truecaller and Google. |
| 🧑 **Name** | Generates likely usernames and opens ready-made searches on Google, LinkedIn, Facebook, Instagram, X, GitHub and Telegram. |
| 🌐 **Domain** | WHOIS, DNS records, SPF/DMARC check and subdomains from certificate logs. |
| 📡 **IP** | Approximate location, ISP, network flags (VPN/hosting) and open ports. |
| ✈️ **Telegram** | Reads a public `t.me` profile: name, bio, type and photo. |
| 🕵️ **Dorks** | Builds advanced Google searches for any text and opens them with one tap. |
| 🖼 **Image** | Send a photo for reverse-search links, or send it as a **File** to read EXIF data (camera, date, GPS). |
| ↪️ **Forward** | Forward any message to see the sender's ID, name and username. |
| ⚡ **Auto** | Send anything and the bot detects what it is and offers the right scans. |

**Also included**
- Button menu under the text box (no slash commands needed)
- Built-in Help center explaining every tool
- Owner-only access: nobody else can use your bot
- Long results are split safely and attached as files when needed

---

## 🚀 Quick start (local)

**Requirements:** Python 3.11+ and a bot token from [@BotFather](https://t.me/BotFather).

```bash
# 1. Create a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create your .env file (copy .env.example) and fill it in
# 4. Run
python bot.py
```

Open your bot in Telegram and send `/start`.

### Environment variables

Create a `.env` file in the project folder:

```env
BOT_TOKEN=your token from @BotFather
OWNER_ID=your numeric Telegram ID
DEFAULT_REGION=ET
INCLUDE_ADULT=0
```

| Variable | Required | Description |
|---|---|---|
| `BOT_TOKEN` | ✅ | Token from @BotFather |
| `OWNER_ID` | ✅ | Your Telegram user ID (get it from [@userinfobot](https://t.me/userinfobot)). Only this user can use the bot. |
| `DEFAULT_REGION` | optional | Country code used to read local phone numbers like `0911...` (default `ET`) |
| `INCLUDE_ADULT` | optional | `1` to include adult sites in username scans, `0` to hide them (default `0`) |

> Never commit your `.env` file. It is already listed in `.gitignore`.

---

## ☁️ Deploy on Render (free)

1. Push the project to a **private** GitHub repo (without `.env`).
2. On [Render](https://render.com): **New → Web Service** and connect the repo.
3. Use these settings:

| Field | Value |
|---|---|
| Language | Python 3 |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `python bot.py` |
| Instance Type | Free |

4. Add the environment variables: `BOT_TOKEN`, `OWNER_ID`, `DEFAULT_REGION`, `INCLUDE_ADULT`, and `PYTHON_VERSION=3.11.9`.
5. Deploy and check the logs for `Health server listening`.

**Keep it awake 24/7:** Render's free plan sleeps after 15 minutes without traffic. Create a free [UptimeRobot](https://uptimerobot.com) HTTP monitor that pings your Render URL every 5 minutes. The bot opens a tiny health page (`/` and `/health`) for this purpose. It only starts when Render provides a `PORT`, so local runs are unaffected.

> Only run **one copy** of the bot per token. If it also runs on your PC, Telegram returns a "Conflict" error.

---

## 📁 Project structure

```
├── bot.py             # Telegram bot: menu, buttons, help center, handlers
├── module.py          # All lookups: email, phone, domain, IP, Telegram, EXIF...
├── checker.py         # Async username scanner (aiohttp)
├── requirements.txt   # Python dependencies
├── .env.example       # Environment variable template
└── .gitignore
```

## 🧰 Tech stack

- [aiogram 3](https://github.com/aiogram/aiogram): Telegram bot framework
- [aiohttp](https://github.com/aio-libs/aiohttp): async HTTP requests
- [WhatsMyName](https://github.com/WebBreacher/WhatsMyName): site list for username checks (refreshed weekly)
- [holehe](https://github.com/megadose/holehe): email registration checks
- [phonenumbers](https://github.com/daviddrysdale/python-phonenumbers): phone parsing
- dnspython, python-whois, Pillow: DNS, WHOIS and EXIF reading
- Free public APIs: Gravatar, XposedOrNot, crt.sh, ip-api, Shodan InternetDB

---

## ⚠️ Limitations

- Results are **leads, not proof**. Always confirm before drawing conclusions.
- Username scans can include false positives, and common names match many people.
- The phone tool cannot reveal the owner's name.
- IP location is usually the ISP's hub, not an exact address.
- Free APIs can be slow or rate-limited, so retry after a minute.
- Telegram strips EXIF from normal photos. Send images as a **File** to read EXIF.
- On Render's free plan the instance is small, so `/email` scans can take 1-2 minutes.

## 🔒 Privacy & responsible use

- Only publicly available information is used.
- The bot is locked to a single owner ID.
- Do not use it for stalking, harassment or any illegal activity.