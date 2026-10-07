"""OSINT lookup modules. Every lookup returns a Result (text + buttons + optional file)."""
from __future__ import annotations

import asyncio
import hashlib
import io
import ipaddress
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape, unescape
from urllib.parse import quote, quote_plus

import aiohttp
import dns.asyncresolver
import phonenumbers
import whois
from phonenumbers import PhoneNumberType, carrier, geocoder
from phonenumbers import timezone as pn_tz
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

import checker

UA = {"User-Agent": checker.BASE_HEADERS["User-Agent"]}
BAR = "━━━━━━━━━━━━━━━━━━"
INCLUDE_ADULT = os.getenv("INCLUDE_ADULT", "0") == "1"


@dataclass
class Result:
    text: str
    links: list[tuple[str, str]] = field(default_factory=list)  # (label, url)
    actions: list[tuple[str, str, str]] = field(default_factory=list)  # (label, kind, target)
    file: tuple[str, bytes] | None = None


class Code(str):
    """Marks a value to be shown in copyable monospace."""


# ───────────────────────── formatting helpers ─────────────────────────
def e(x) -> str:
    return escape(str(x))


def _empty(v) -> bool:
    return v is None or (isinstance(v, (str, list, tuple, set, dict)) and len(v) == 0)


def head(icon: str, title: str, target: str = "") -> str:
    sub = f"\n<code>{e(target)}</code>" if target else ""
    return f"{icon} <b>{e(title.upper())}</b>{sub}\n{BAR}\n"


def section(icon: str, title: str, count=None) -> str:
    c = f"  ·  <b>{count}</b>" if count is not None else ""
    return f"{icon} <b>{e(title)}</b>{c}\n"


def tree(items) -> str:
    """Nice ├ └ list. Empty values are skipped."""
    items = [(label, v) for label, v in items if not _empty(v)]
    lines = []
    for i, (label, v) in enumerate(items):
        branch = "└" if i == len(items) - 1 else "├"
        val = f"<code>{e(v)}</code>" if isinstance(v, Code) else e(v)
        lines.append(f"{branch} <b>{e(label)}</b>  {val}")
    return "\n".join(lines) + ("\n" if lines else "")


def row(label: str, value) -> str:  # kept for compatibility
    return "" if _empty(value) else f"▸ <b>{e(label)}:</b> {e(value)}\n"


def google(q: str) -> str:
    return "https://www.google.com/search?q=" + quote_plus(q)


async def _json(url: str, timeout: int = 15):
    try:
        async with aiohttp.ClientSession(headers=UA) as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                if r.status != 200:
                    return None
                return await r.json(content_type=None)
    except Exception:
        return None


async def _text(url: str, timeout: int = 15) -> tuple[int, str]:
    try:
        async with aiohttp.ClientSession(headers=UA) as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                return r.status, await r.text(errors="ignore")
    except Exception:
        return 0, ""


async def _dns(name: str, rtype: str) -> list[str]:
    try:
        ans = await dns.asyncresolver.resolve(name, rtype, lifetime=6)
        return [r.to_text() for r in ans]
    except Exception:
        return []


# ───────────────────────── detection ─────────────────────────
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
TG_RE = re.compile(r"^(?:https?://)?t\.me/([A-Za-z0-9_]{4,32})/?$")


def detect(text: str) -> str:
    t = text.strip()
    if EMAIL_RE.match(t):
        return "email"
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if TG_RE.match(t):
        return "tg"
    if re.fullmatch(r"\+?[\d\s().-]{7,20}", t) and sum(c.isdigit() for c in t) >= 7:
        return "phone"
    if DOMAIN_RE.match(t):
        return "domain"
    if " " in t:
        return "name"
    if checker.USERNAME_RE.match(t.lstrip("@")):
        return "username"
    return "name"


# ───────────────────────── username ─────────────────────────
CAT_ICON = {
    "social": "💬", "coding": "💻", "gaming": "🎮", "music": "🎵", "video": "🎬",
    "images": "🖼", "art": "🎨", "blog": "✍️", "business": "💼", "finance": "💰",
    "news": "📰", "shopping": "🛒", "dating": "❤️", "political": "🏛", "health": "🩺",
    "hobby": "🧩", "tech": "🛠", "misc": "📦", "archived": "🗄",
}


async def username(raw: str) -> Result:
    name = raw.strip().lstrip("@")
    if not checker.USERNAME_RE.match(name):
        return Result("❌ Username must be 2-40 chars: letters, numbers, <code>. _ -</code>")

    t0 = time.time()
    hits, total = await checker.scan(name)
    if not INCLUDE_ADULT:
        hits = [h for h in hits if "nsfw" not in h["cat"].lower()]
    secs = int(time.time() - t0)

    out = head("👤", "Username Scan", name)
    google_btn = [("🔍 Google", google(f'"{name}"'))]
    if not hits:
        out += "❌ <b>No profiles found</b>\n" + tree([("Sites checked", total), ("Time", f"{secs}s")])
        return Result(out, links=google_btn)

    out += f"✅ <b>{len(hits)} profiles found</b>\n"
    out += tree([("Sites checked", total), ("Time", f"{secs}s")])
    out += "\n<i>Open a link to confirm - some hits can be false positives.</i>"

    groups: dict[str, list[dict]] = {}
    for h in hits:
        groups.setdefault(h["cat"], []).append(h)
    for cat, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        links = [f'<a href="{escape(h["url"], quote=True)}">{e(h["site"])}</a>' for h in items]
        lines = [" · ".join(links[i:i + 8]) for i in range(0, len(links), 8)]
        out += f"\n\n{CAT_ICON.get(cat.lower(), '📌')} <b>{e(cat.upper())}</b>  ·  {len(items)}\n" + "\n".join(lines)

    report = "\n".join(f"{h['cat']}\t{h['site']}\t{h['url']}" for h in hits)
    return Result(
        out,
        links=google_btn,
        actions=[("✈️ Telegram lookup", "tg", name)],
        file=(f"username_{name}.txt", report.encode()),
    )


# ───────────────────────── email ─────────────────────────
async def _gravatar(addr: str) -> dict | None:
    h = hashlib.md5(addr.encode()).hexdigest()
    data = await _json(f"https://gravatar.com/{h}.json")
    try:
        return data["entry"][0]
    except Exception:
        return None


async def _holehe(addr: str, timeout: int = 150) -> list[str] | None:
    cmd = [sys.executable, "-c", "from holehe.core import main; main()",
           addr, "--only-used", "--no-color", "--no-clear"]
    try:
        p = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, _ = await asyncio.wait_for(p.communicate(), timeout)
        except asyncio.TimeoutError:
            p.kill()
            return None
    except Exception:
        return None
    text = re.sub(r"\x1b\[[0-9;]*m", "", out.decode(errors="ignore"))
    return sorted({m.group(1) for m in re.finditer(r"^\[\+\]\s+(\S+)", text, re.M)})


async def _breach(addr: str) -> tuple[str, list[str]]:
    try:
        async with aiohttp.ClientSession(headers=UA) as s:
            async with s.get(
                f"https://api.xposedornot.com/v1/check-email/{quote(addr)}",
                timeout=aiohttp.ClientTimeout(total=20),
            ) as r:
                if r.status == 404:
                    return "clean", []
                if r.status != 200:
                    return "error", []
                data = await r.json(content_type=None)
    except Exception:
        return "error", []
    raw = data.get("breaches") or []
    names = sorted({n for g in raw for n in (g if isinstance(g, list) else [g])})
    return ("ok", names) if names else ("clean", [])


def _breach_body(status: str, names: list[str]) -> str:
    if status == "error":
        return "⚠️ Breach service unavailable right now"
    if status == "clean":
        return "✅ Not found in known breaches"
    body = ", ".join(e(n) for n in names[:60]) + (f" +{len(names) - 60} more" if len(names) > 60 else "")
    return f"🚨 <b>Found in {len(names)} breaches</b>\n<blockquote expandable>{body}</blockquote>"


async def breach(raw: str) -> Result:
    addr = raw.strip().lower()
    if not EMAIL_RE.match(addr):
        return Result("❌ Invalid email address.")
    status, names = await _breach(addr)
    out = head("💥", "Breach Check", addr) + _breach_body(status, names)
    out += "\n\n<i>Shows which leaks the email appeared in - never passwords.</i>"
    return Result(out, links=[("🛡 Have I Been Pwned", f"https://haveibeenpwned.com/account/{quote(addr)}")])


async def email(raw: str) -> Result:
    addr = raw.strip().lower()
    if not EMAIL_RE.match(addr):
        return Result("❌ Invalid email address.")
    local, domain = addr.split("@", 1)

    mx, grav, reg, br = await asyncio.gather(
        _dns(domain, "MX"), _gravatar(addr), _holehe(addr), _breach(addr))

    mx_host = sorted(mx)[0].split()[-1].rstrip(".") if mx else ""
    parts = [
        head("📧", "Email Intelligence", addr) + section("📬", "Mail server")
        + tree([("Domain", domain),
                ("Status", f"✅ {mx_host}" if mx else "❌ no MX record (can't receive mail)")]).rstrip("\n")
    ]

    if grav:
        body = tree([("Name", grav.get("displayName")), ("Username", grav.get("preferredUsername")),
                     ("Location", grav.get("currentLocation")), ("About", (grav.get("aboutMe") or "")[:200])])
        body += "".join(
            f'• <a href="{escape(a.get("url", ""), quote=True)}">{e(a.get("shortname", "account"))}</a>\n'
            for a in (grav.get("accounts") or [])[:8])
        body = body.rstrip("\n") or "Profile exists but has no public details"
    else:
        body = "No public Gravatar profile"
    parts.append(section("🖼", "Gravatar") + body)

    if reg is None:
        parts.append(section("🌐", "Registered on") + "⚠️ holehe unavailable or timed out\n"
                     "<i>Install it with</i> <code>pip install holehe</code>")
    elif not reg:
        parts.append(section("🌐", "Registered on", 0) + "No registrations detected")
    else:
        parts.append(section("🌐", "Registered on", len(reg))
                     + "<blockquote expandable>" + "\n".join(e(s) for s in reg[:80]) + "</blockquote>")

    parts.append(section("💥", "Breaches") + _breach_body(*br))

    actions = []
    if checker.USERNAME_RE.match(local):
        actions.append((f"👤 Scan “{local[:20]}”", "user", local))
    return Result(
        "\n\n".join(parts),
        links=[
            ("🔍 Google", google(f'"{addr}"')),
            ("📋 Pastes", google(f'"{addr}" site:pastebin.com')),
            ("🧬 Epieos", f"https://epieos.com/?q={quote(addr)}&t=email"),
            ("🛡 HIBP", f"https://haveibeenpwned.com/account/{quote(addr)}"),
        ],
        actions=actions,
    )


# ───────────────────────── phone ─────────────────────────
PT = {
    PhoneNumberType.MOBILE: "Mobile", PhoneNumberType.FIXED_LINE: "Landline",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Landline or mobile", PhoneNumberType.TOLL_FREE: "Toll-free",
    PhoneNumberType.PREMIUM_RATE: "Premium rate", PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "Personal", PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "UAN", PhoneNumberType.VOICEMAIL: "Voicemail",
    PhoneNumberType.UNKNOWN: "Unknown",
}


async def phone(raw: str, region: str = "ET") -> Result:
    try:
        n = phonenumbers.parse(raw.strip(), region)
    except phonenumbers.NumberParseException as ex:
        return Result(f"❌ Can't parse that number: {e(ex)}\nTip: use the format <code>+251911234567</code>")

    fmt = phonenumbers.format_number
    e164 = fmt(n, phonenumbers.PhoneNumberFormat.E164)
    intl = fmt(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    nat = fmt(n, phonenumbers.PhoneNumberFormat.NATIONAL)
    digits = e164.lstrip("+")
    rc = phonenumbers.region_code_for_number(n) or region

    valid = phonenumbers.is_valid_number(n)
    parts = [
        head("📱", "Phone Intelligence", intl) + section("📍", "Details")
        + tree([
            ("Valid", "✅ yes" if valid else "❌ no"),
            ("Country", geocoder.country_name_for_number(n, "en")),
            ("Region", geocoder.description_for_number(n, "en")),
            ("Carrier", carrier.name_for_number(n, "en")),
            ("Line type", PT.get(phonenumbers.number_type(n), "Unknown")),
            ("Timezone", ", ".join(pn_tz.time_zones_for_number(n))),
        ]).rstrip("\n"),
        section("🔢", "Formats") + tree([
            ("E.164", Code(e164)), ("International", Code(intl)), ("National", Code(nat))]).rstrip("\n"),
        "<i>Carrier shows the original operator - ported numbers can differ. "
        "WhatsApp/Telegram buttons only open a chat if the number is registered there.</i>",
    ]
    return Result(
        "\n\n".join(parts),
        links=[
            ("💬 WhatsApp", f"https://wa.me/{digits}"),
            ("✈️ Telegram", f"https://t.me/+{digits}"),
            ("📞 Truecaller", f"https://www.truecaller.com/search/{rc.lower()}/{n.national_number}"),
            ("🔍 Google", google(f'"{e164}" OR "{intl}" OR "{nat}"')),
        ],
    )


# ───────────────────────── name ─────────────────────────
def _variants(full: str) -> list[str]:
    parts = re.sub(r"[^A-Za-z0-9 ]", "", full).lower().split()
    if not parts:
        return []
    if len(parts) == 1:
        return [parts[0]]
    f, l = parts[0], parts[-1]
    cand = [f + l, f + "." + l, f + "_" + l, l + f, l + "." + f, f[0] + l, f + l[0], f[0] + "." + l, f, l]
    seen, out = set(), []
    for c in cand:
        if c not in seen and checker.USERNAME_RE.match(c):
            seen.add(c)
            out.append(c)
    return out


async def name_search(full: str) -> Result:
    full = " ".join(full.split())
    q = f'"{full}"'
    variants = _variants(full)
    dorks = [
        ("🔍 Google", q),
        ("💼 LinkedIn", f"{q} site:linkedin.com/in"),
        ("📘 Facebook", f"{q} site:facebook.com"),
        ("📸 Instagram", f"{q} site:instagram.com"),
        ("🐦 X / Twitter", f"{q} (site:x.com OR site:twitter.com)"),
        ("💻 GitHub", f"{q} site:github.com"),
        ("✈️ Telegram", f"{q} site:t.me"),
        ("📄 Documents", f"{q} (filetype:pdf OR filetype:docx)"),
    ]
    out = head("🧑", "Name Search", full)
    if variants:
        out += section("🧩", "Likely usernames", len(variants))
        out += " · ".join(f"<code>{e(v)}</code>" for v in variants)
        out += "\n\n<i>Tap a 👤 button to scan that username on 690+ sites.</i>"
    else:
        out += "No Latin-letter username guesses for this name. Use the search buttons below."
    out += "\n<i>Names are ambiguous - confirm with a photo, city, or workplace.</i>"
    return Result(
        out,
        links=[(label, google(d)) for label, d in dorks],
        actions=[(f"👤 Scan “{v}”", "user", v) for v in variants[:4]],
    )


# ───────────────────────── dorks ─────────────────────────
async def dorks(target: str) -> Result:
    t = target.strip()
    q = f'"{t}"'
    items = [
        ("🔍 Exact match", q),
        ("📋 Pastebin", f"{q} site:pastebin.com"),
        ("💻 GitHub", f"{q} site:github.com"),
        ("✈️ Telegram", f"{q} site:t.me"),
        ("📄 Documents", f"{q} (filetype:pdf OR filetype:xlsx OR filetype:docx)"),
        ("🔐 Leaks", f"{q} (password OR leak OR dump)"),
    ]
    out = head("🕵️", "Dork Builder", t) + section("📝", "Queries", len(items))
    out += "<blockquote expandable>" + "\n".join(e(d) for _, d in items) + "</blockquote>"
    out += "\n\n<i>Tap a button to open that search.</i>"
    links = [(lbl, google(d)) for lbl, d in items]
    links += [
        ("🦆 DuckDuckGo", "https://duckduckgo.com/?q=" + quote_plus(q)),
        ("🇷🇺 Yandex", "https://yandex.com/search/?text=" + quote_plus(q)),
        ("🅱️ Bing", "https://www.bing.com/search?q=" + quote_plus(q)),
    ]
    return Result(out, links=links)


# ───────────────────────── domain ─────────────────────────
def _first(v):
    return v[0] if isinstance(v, (list, tuple)) and v else v


def _fmt_date(v) -> str | None:
    v = _first(v)
    return v.strftime("%Y-%m-%d") if hasattr(v, "strftime") else (str(v) if v else None)


def _whois(domain: str):
    try:
        return whois.whois(domain)
    except Exception:
        return None


async def _subdomains(domain: str) -> list[str] | None:
    data = await _json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
    if not data:
        return None
    subs = set()
    for r in data:
        for n in str(r.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain) and n != domain:
                subs.add(n)
    return sorted(subs)


async def domain(raw: str) -> Result:
    d = raw.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not DOMAIN_RE.match(d):
        return Result("❌ Invalid domain. Example: <code>example.com</code>")

    w, a, aaaa, mx, ns, txt, dmarc, subs = await asyncio.gather(
        asyncio.to_thread(_whois, d), _dns(d, "A"), _dns(d, "AAAA"), _dns(d, "MX"),
        _dns(d, "NS"), _dns(d, "TXT"), _dns("_dmarc." + d, "TXT"), _subdomains(d))

    if w and (w.get("domain_name") or w.get("registrar")):
        created = _first(w.get("creation_date"))
        age = f" (~{datetime.now(timezone.utc).year - created.year}y old)" if hasattr(created, "year") else ""
        who = tree([
            ("Registrar", w.get("registrar")),
            ("Created", (_fmt_date(w.get("creation_date")) or "") + age),
            ("Expires", _fmt_date(w.get("expiration_date"))),
            ("Organization", _first(w.get("org"))),
            ("Country", _first(w.get("country"))),
        ]).rstrip("\n") or "WHOIS record is private"
    else:
        who = "No WHOIS data (private or unsupported TLD)"
    parts = [head("🌐", "Domain Recon", d) + section("📇", "WHOIS") + who]

    spf = any("v=spf1" in t_.lower() for t_ in txt)
    dns_txt = tree([
        ("A", ", ".join(a)),
        ("AAAA", ", ".join(aaaa[:3])),
        ("MX", ", ".join(sorted(x.split()[-1].rstrip(".") for x in mx))),
        ("NS", ", ".join(sorted(x.rstrip(".") for x in ns))),
        ("Email security", f"SPF {'✅' if spf else '❌'}  ·  DMARC {'✅' if dmarc else '❌'}"),
    ]).rstrip("\n")
    if txt:
        dns_txt += "\n<blockquote expandable>" + "\n".join(e(t_[:90]) for t_ in txt[:10]) + "</blockquote>"
    parts.append(section("📡", "DNS") + dns_txt)

    file = None
    if subs is None:
        parts.append(section("🧬", "Subdomains") + "⚠️ crt.sh didn't respond - try again in a minute")
    elif not subs:
        parts.append(section("🧬", "Subdomains", 0) + "None found in certificate logs")
    else:
        body = "<blockquote expandable>" + "\n".join(e(s) for s in subs[:50])
        body += (f"\n… +{len(subs) - 50} more (see file)" if len(subs) > 50 else "") + "</blockquote>"
        parts.append(section("🧬", "Subdomains", len(subs)) + body)
        if len(subs) > 50:
            file = (f"subdomains_{d}.txt", "\n".join(subs).encode())

    return Result(
        "\n\n".join(parts),
        links=[
            ("🛡 VirusTotal", f"https://www.virustotal.com/gui/domain/{d}"),
            ("🕰 Wayback", f"https://web.archive.org/web/*/{d}"),
            ("🔬 urlscan", f"https://urlscan.io/search/#{quote(d)}"),
            ("🧱 BuiltWith", f"https://builtwith.com/{d}"),
            ("📜 crt.sh", f"https://crt.sh/?q={d}"),
            ("🔍 Shodan", f"https://www.shodan.io/search?query={quote(d)}"),
        ],
        file=file,
    )


async def ip_lookup(raw: str) -> Result:
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError:
        return Result("❌ Invalid IP address.")
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        return Result(head("📡", "IP Intel", str(addr)) + "This is a private/reserved address - nothing public to look up.")
    ip = str(addr)

    fields = ("status,message,continent,country,regionName,city,zip,lat,lon,timezone,"
              "isp,org,as,reverse,mobile,proxy,hosting,query")
    geo, idb = await asyncio.gather(
        _json(f"http://ip-api.com/json/{ip}?fields={fields}"),
        _json(f"https://internetdb.shodan.io/{ip}"))

    links = [
        ("🔍 Shodan", f"https://www.shodan.io/host/{ip}"),
        ("🚨 AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}"),
        ("🛡 VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip}"),
    ]
    parts = []
    if geo and geo.get("status") == "success":
        flags = [n for k, n in (("proxy", "VPN/Proxy"), ("hosting", "Hosting/Datacenter"),
                                ("mobile", "Mobile network")) if geo.get(k)]
        parts.append(head("📡", "IP Intel", ip) + section("📍", "Location (approximate)") + tree([
            ("Country", geo.get("country")),
            ("Region / City", ", ".join(x for x in (geo.get("regionName"), geo.get("city")) if x)),
            ("Timezone", geo.get("timezone")),
        ]).rstrip("\n"))
        parts.append(section("🏢", "Network") + tree([
            ("ISP", geo.get("isp")), ("Org", geo.get("org")), ("ASN", geo.get("as")),
            ("Reverse DNS", geo.get("reverse")), ("Flags", ", ".join(flags) or "none"),
        ]).rstrip("\n"))
        if geo.get("lat") is not None:
            links.insert(0, ("🗺 Map", f"https://www.google.com/maps?q={geo['lat']},{geo['lon']}"))
    else:
        parts.append(head("📡", "IP Intel", ip) + "⚠️ Geolocation service unavailable")

    exposure = "Nothing indexed"
    if idb and any(idb.get(k) for k in ("ports", "hostnames", "tags", "vulns")):
        vulns = idb.get("vulns", [])
        exposure = tree([
            ("Open ports", ", ".join(map(str, idb.get("ports", [])))),
            ("Hostnames", ", ".join(idb.get("hostnames", [])[:6])),
            ("Tags", ", ".join(idb.get("tags", []))),
            ("Known CVEs", f"{len(vulns)} - " + ", ".join(vulns[:8]) if vulns else ""),
        ]).rstrip("\n")
    parts.append(section("🔓", "Exposure (Shodan InternetDB)") + exposure)
    parts.append("<i>IP location is usually the ISP's hub, not the person's exact address.</i>")
    return Result("\n\n".join(parts), links=links)


def _strip(html: str) -> str:
    return unescape(re.sub(r"<[^>]+>", "", re.sub(r"<br\s*/?>", "\n", html))).strip()


async def telegram(raw: str) -> Result:
    t = raw.strip()
    if t.isdigit():
        return Result(
            head("✈️", "Telegram ID", t) + "Numeric IDs can't be resolved by the public web.\n"
            "The button opens the profile only if you already share a chat with that user.",
            links=[("👤 Open profile", f"tg://user?id={t}")],
        )
    m = TG_RE.match(t)
    uname = m.group(1) if m else t.lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_]{4,32}", uname):
        return Result("❌ Telegram usernames are 4-32 chars: letters, numbers, underscore.")

    status, html = await _text(f"https://t.me/{uname}")
    og = re.search(r'<meta property="og:title" content="([^"]*)"', html)
    title = unescape(og.group(1)) if og else ""
    out = head("✈️", "Telegram Lookup", "@" + uname)

    if status != 200 or not title or title.startswith("Telegram:"):
        out += "❌ No public profile found\n<i>The username may be free, private, or banned.</i>"
        return Result(out, actions=[("👤 Username scan", "user", uname)])

    desc = re.search(r'<div class="tgme_page_description[^"]*"[^>]*>(.*?)</div>', html, re.S)
    extra = re.search(r'<div class="tgme_page_extra"[^>]*>(.*?)</div>', html, re.S)
    img = re.search(r'<meta property="og:image" content="([^"]*)"', html)
    extra_t = _strip(extra.group(1)) if extra else ""
    kind = ("Channel / group" if re.search(r"subscriber|member", extra_t, re.I)
            else "Bot" if uname.lower().endswith("bot") else "User")

    out += "✅ <b>Public profile found</b>\n" + tree([
        ("Name", title),
        ("Type", kind),
        ("Bio", _strip(desc.group(1))[:400] if desc else ""),
        ("Stats", extra_t if extra_t and not extra_t.startswith("@") else ""),
    ])
    links = [("✈️ Open in Telegram", f"https://t.me/{uname}"),
             ("🔍 Google", google(f'"@{uname}" OR "t.me/{uname}"'))]
    if img:
        links.append(("🖼 Profile photo", unescape(img.group(1))))
    return Result(out, links=links, actions=[("👤 Username scan", "user", uname)])


def _dms(vals, ref) -> float:
    d, m, s = (float(x) for x in vals)
    dec = d + m / 60 + s / 3600
    return -dec if str(ref).upper() in ("S", "W") else dec


REVERSE_LINKS = [
    ("🔎 Google Lens", "https://lens.google.com/"),
    ("🇷🇺 Yandex Images", "https://yandex.com/images/"),
    ("👁 TinEye", "https://tineye.com/"),
    ("🅱️ Bing Visual", "https://www.bing.com/visualsearch"),
]


def exif_report(data: bytes) -> Result:
    """Reads EXIF from the start of an image file (works on a truncated download)."""
    out = head("📷", "Image EXIF")
    try:
        img = Image.open(io.BytesIO(data))
        ex = img.getexif()
        info = {TAGS.get(k, k): v for k, v in ex.items()}
        try:
            info.update({TAGS.get(k, k): v for k, v in ex.get_ifd(0x8769).items()})
        except Exception:
            pass
        try:
            gps = {GPSTAGS.get(k, k): v for k, v in ex.get_ifd(0x8825).items()}
        except Exception:
            gps = {}
        size = f"{img.width}×{img.height} {img.format or ''}".strip()
    except Exception:
        return Result(out + "❌ Couldn't read this image.\n<i>Unsupported format (for example HEIC) or not an image.</i>",
                      links=REVERSE_LINKS)

    def clean(v):
        if isinstance(v, bytes):
            return v.decode(errors="ignore").strip("\x00 ")
        return str(v).strip() if v is not None else None

    out += section("🖼", "Photo") + tree([
        ("Size", size),
        ("Camera", " ".join(x for x in (clean(info.get("Make")), clean(info.get("Model"))) if x)),
        ("Lens", clean(info.get("LensModel"))),
        ("Software", clean(info.get("Software"))),
        ("Taken", clean(info.get("DateTimeOriginal"))),
        ("Modified", clean(info.get("DateTime"))),
        ("Artist", clean(info.get("Artist"))),
        ("Copyright", clean(info.get("Copyright"))),
    ]).rstrip("\n")

    links = []
    if gps.get("GPSLatitude") and gps.get("GPSLongitude"):
        try:
            lat = _dms(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
            lon = _dms(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
            out += "\n\n" + section("📍", "GPS location") + tree([("Coordinates", Code(f"{lat:.6f}, {lon:.6f}"))]).rstrip("\n")
            links.append(("🗺 Open map", f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"))
        except Exception:
            out += "\n\n📍 GPS data present but unreadable"
    else:
        out += "\n\n📍 <b>No GPS data</b>"
    if not info and not gps:
        out += "\n<i>No EXIF at all - the app that sent this image stripped it.</i>"
    return Result(out, links=links + REVERSE_LINKS)


def photo_tip() -> Result:
    text = (head("📷", "Image Tools")
            + "Telegram removes EXIF from normal photos.\n\n"
            + tree([("EXIF / GPS", "resend the image as a File (📎 → File)"),
                    ("Reverse search", "open a site below and upload the image")]).rstrip("\n"))
    return Result(text, links=REVERSE_LINKS)