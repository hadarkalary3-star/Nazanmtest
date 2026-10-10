import asyncio, json, os, plistlib, re, shutil, subprocess, time, uuid, zipfile
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

from aiohttp import web
from aiogram import Bot, Dispatcher, Router, F
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (Message, CallbackQuery, InlineKeyboardMarkup,
                           InlineKeyboardButton)

# ───────── ڕێکخستن ─────────
TOKEN = os.getenv("BOT_TOKEN", "BOT_TOKEN")
OWNER_ID = 8038533940
OWNER_USER = "X_MAM6"
_rd = os.getenv("RAILWAY_PUBLIC_DOMAIN")
DOMAIN = os.getenv("DOMAIN") or (f"https://{_rd}" if _rd else "https://example.com")
WEBROOT = os.getenv("WEBROOT", "/data/apps")          # لینکەکان لێرە دەمێنن
PORT = int(os.getenv("PORT", "8080"))
LOCAL_API = os.getenv("LOCAL_API") or None            # بۆ IPA گەورە (تا 4GB)
LINK_TTL = 7200                                       # چەند چرکە لینکەکە بمێنێتەوە

DATA = Path(os.getenv("DATA_DIR", "data"))
WORK = DATA / "work"
FILE = DATA / "emojis.json"
KEYFILE = DATA / "secret.key"

# key: (ئیمۆجی ئاسایی, ناو)
SLOTS = {
    "lock":    ("🔒", "قوفڵ"),
    "deny":    ("🚫", "ڕێگەپێنەدراو / هەڵوەشاندنەوە"),
    "sad":     ("😔", "ببورە"),
    "crown":   ("👑", "سەرۆک"),
    "sparkle": ("✨", "درەوشاوە"),
    "id":      ("🆔", "ئایدی"),
    "copy":    ("📋", "کۆپی"),
    "send":    ("📨", "ناردن"),
    "wave":    ("👋", "سڵاو"),
    "gear":    ("⚙️", "ڕێکخستن"),
    "ok":      ("✅", "تەواو"),
    "skip":    ("⏭", "بازدان"),
    "cert":    ("🔐", "بڕوانامە"),
    "sign":    ("✍️", "واژۆکردن"),
    "ipa":     ("📦", "IPA"),
    "key":     ("🔑", "پاسۆرد"),
    "file":    ("📄", "فایل"),
    "warn":    ("⚠️", "ئاگادارکردنەوە"),
    "bad":     ("❌", "هەڵە"),
    "down":    ("⬇️", "دابەزاندن"),
    "link":    ("🔗", "لینک"),
    "clock":   ("⏳", "کات"),
    "phone":   ("📲", "دامەزراندن"),
    "bolt":    ("⚡", "خێرا"),
    "user":    ("👤", "کەس"),
}
KEYS = list(SLOTS)

DATA.mkdir(exist_ok=True, parents=True)
WORK.mkdir(exist_ok=True, parents=True)


# ───────── ئیمۆجی پریمیۆم ─────────
def _load(p, default):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return default


IDS = _load(FILE, {})


def save_ids():
    FILE.write_text(json.dumps(IDS), encoding="utf-8")


def E(k):
    f = SLOTS[k][0]
    if k in IDS:
        return f'<tg-emoji emoji-id="{IDS[k]}">{f}</tg-emoji>'
    return f


def B(k, label, style=None, **kw):
    """style: primary=شین، success=سەوز، danger=سوور"""
    extra = {}
    if style:
        extra["style"] = style
    if k in IDS:
        extra["icon_custom_emoji_id"] = IDS[k]
        text = label
    else:
        text = f"{SLOTS[k][0]} {label}"
    return InlineKeyboardButton(text=text, **extra, **kw)


def kb(*rows):
    return InlineKeyboardMarkup(inline_keyboard=[list(r) for r in rows])


CANCEL = kb([B("deny", "هەڵوەشاندنەوە", "danger", callback_data="cancel")])


# ───────── کەسەکان و پاراستنی داتا ─────────
ALLOWED = set(_load(DATA / "allowed.json", []))


def allowed(uid):
    return uid == OWNER_ID or uid in ALLOWED


def _fernet():
    if not KEYFILE.exists():
        KEYFILE.write_bytes(Fernet.generate_key())
        os.chmod(KEYFILE, 0o600)
    return Fernet(KEYFILE.read_bytes())


FER = _fernet()


def udir(uid):
    p = DATA / "users" / str(uid)
    p.mkdir(parents=True, exist_ok=True)
    return p


def uinfo(uid):
    return _load(udir(uid) / "info.json", None)


class UserError(Exception):
    pass


# ───────── خوێندنەوەی p12 ─────────
def read_p12(path, pw):
    """-> ("ok", cert) | ("pw", None) هەڵەی پاسۆرد | ("bad", None) فایلی تێکچوو"""
    env = {**os.environ, "P12PW": pw}
    for legacy in (True, False):
        cmd = ["openssl", "pkcs12", "-in", str(path), "-nokeys", "-clcerts",
               "-passin", "env:P12PW"]
        if legacy:
            cmd.append("-legacy")
        try:
            r = subprocess.run(cmd, capture_output=True, env=env, timeout=30)
        except Exception:
            return "bad", None
        err = r.stderr.decode(errors="ignore").lower()
        if r.returncode == 0:
            m = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                          r.stdout, re.S)
            if not m:
                return "bad", None
            return "ok", x509.load_pem_x509_certificate(m.group(0))
        if "mac verify" in err or "invalid password" in err or "wrong password" in err:
            return "pw", None
    return "bad", None


def cert_exp(c):
    d = getattr(c, "not_valid_after_utc", None)
    return d.replace(tzinfo=None) if d else c.not_valid_after


def cert_names(c):
    cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    ou = c.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
    return (cn[0].value if cn else "?"), (ou[0].value if ou else "?")


def now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ───────── خوێندنەوەی mobileprovision ─────────
def read_prov(path):
    raw = Path(path).read_bytes()
    a, b = raw.find(b"<?xml"), raw.rfind(b"</plist>")
    if a < 0 or b < 0:
        return None
    try:
        return plistlib.loads(raw[a:b + 8])
    except Exception:
        return None


def prov_bundle(p):
    ent = p.get("Entitlements", {})
    aid = ent.get("application-identifier", "")
    prefix = (p.get("ApplicationIdentifierPrefix") or [""])[0]
    return aid[len(prefix) + 1:] if prefix and aid.startswith(prefix + ".") else aid


# ───────── خوێندنەوەی IPA ─────────
def ipa_info(path):
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n):
                d = plistlib.loads(z.read(n))
                return {
                    "id": d.get("CFBundleIdentifier", ""),
                    "ver": d.get("CFBundleShortVersionString") or d.get("CFBundleVersion", "1"),
                    "name": d.get("CFBundleDisplayName") or d.get("CFBundleName", "App"),
                }
    return None


# ───────── ئیمزاکردن ─────────
async def run_zsign(uid, src, out, bundle_id):
    d = udir(uid)
    info = uinfo(uid)
    pw = FER.decrypt(info["pw"].encode()).decode() if info.get("pw") else ""
    cmd = ["zsign", "-k", str(d / "cert.p12"), "-m", str(d / "prov.mobileprovision"),
           "-o", str(out)]
    if pw:
        cmd += ["-p", pw]
    if bundle_id:
        cmd += ["-b", bundle_id]
    cmd.append(str(src))
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    so, se = await proc.communicate()
    ok = proc.returncode == 0 and Path(out).exists()
    return ok, (se or so).decode(errors="ignore").strip()[-200:]


def make_manifest(url, bid, ver, title):
    t, b = escape(title), escape(bid)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>items</key><array><dict>
<key>assets</key><array><dict><key>kind</key><string>software-package</string>
<key>url</key><string>{url}</string></dict></array>
<key>metadata</key><dict><key>bundle-identifier</key><string>{b}</string>
<key>bundle-version</key><string>{escape(ver)}</string>
<key>kind</key><string>software</string><key>title</key><string>{t}</string></dict>
</dict></array></dict></plist>"""


def make_page(link, title):
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title>
<style>body{{background:#111;color:#fff;font-family:-apple-system,sans-serif;
display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0}}
a{{background:#0a84ff;color:#fff;padding:18px 48px;border-radius:16px;font-size:22px;
text-decoration:none}}</style></head><body><h2>{escape(title)}</h2>
<a href="{link}">Install</a></body></html>"""


# ───────── FSM ─────────
class S(StatesGroup):
    wait = State()      # ڕێکخستنی ئیمۆجی


class C(StatesGroup):
    p12 = State()
    pw = State()
    prov = State()


class G(StatesGroup):
    ipa = State()


owner = Router()
guest = Router()
owner.message.filter(lambda m: allowed(m.from_user.id))
owner.callback_query.filter(lambda c: allowed(c.from_user.id))


# ───────── خەڵکی تر ─────────
@guest.message()
async def guest_msg(m: Message):
    uid = m.from_user.id
    req = f"سڵاو سەرۆک 👋\nداوای ئەکتیڤکردنی بۆتەکە دەکەم ✨\n🆔 ئایدی من: {uid}"
    url = f"https://t.me/{OWNER_USER}?text={quote(req)}"
    await m.answer(
        f"{E('lock')} <b>ببورە! ئەم بۆتە تایبەتە</b> {E('deny')}\n\n"
        f"{E('sad')} ئەم بۆتە بۆ تۆ بەردەست نییە.\n"
        f"{E('crown')} ئەگەر دەتەوێت ئەکتیڤ بێت، نامە بۆ سەرۆک بنێرە {E('sparkle')}\n\n"
        f"{E('id')} ئایدی تۆ: <code>{uid}</code>\n"
        f"{E('copy')} <i>(کلیکی لێ بکە بۆ کۆپیکردن)</i>",
        reply_markup=kb([B("send", "ناردنی داواکاری بۆ سەرۆک", "success", url=url)]),
    )


@guest.callback_query()
async def guest_cb(c: CallbackQuery):
    await c.answer("🔒", show_alert=True)


# ───────── پانێلی سەرەکی ─────────
def status_line(uid):
    i = uinfo(uid)
    if not i:
        return f"{E('warn')} هێشتا بڕوانامە دانەنراوە"
    return (f"{E('cert')} <b>{escape(i['cert'])}</b>\n"
            f"{E('clock')} بڕوانامە تا <code>{i['cexp'][:10]}</code> · "
            f"provision تا <code>{i['pexp'][:10]}</code>")


def panel_kb():
    return kb(
        [B("cert", "دانانی بڕوانامە", "primary", callback_data="cert")],
        [B("sign", "واژۆکردنی IPA", "success", callback_data="sign")],
    )


async def show_panel(m: Message, uid):
    await m.answer(
        f"{E('crown')} <b>بەخێربێیت</b> {E('sparkle')}\n\n{status_line(uid)}\n\n"
        f"{E('gear')} ئیمۆجییەکان: /setup",
        reply_markup=panel_kb())


@owner.message(CommandStart())
async def start(m: Message, state: FSMContext):
    await state.clear()
    await show_panel(m, m.from_user.id)


@owner.message(Command("cancel"))
async def cancel_cmd(m: Message, state: FSMContext):
    await state.clear()
    await show_panel(m, m.from_user.id)


@owner.callback_query(F.data == "cancel")
async def cancel_cb(c: CallbackQuery, state: FSMContext):
    await c.answer()
    await state.clear()
    for f in udir(c.from_user.id).glob("pending.*"):
        f.unlink(missing_ok=True)
    await show_panel(c.message, c.from_user.id)


# ───────── بەشی ١: دانانی بڕوانامە ─────────
@owner.callback_query(F.data == "cert")
async def cert_start(c: CallbackQuery, state: FSMContext):
    await c.answer()
    await state.set_state(C.p12)
    await c.message.answer(
        f"{E('cert')} <b>هەنگاوی ١/٢</b>\n{E('file')} فایلی <code>.p12</code> بنێرە",
        reply_markup=CANCEL)


async def save_doc(bot, doc, dest: Path):
    """فایل لە تێلێگرام وەردەگرێت (لۆکاڵ: بێ کۆپی ئەگەر بکرێت، تا 4GB)"""
    f = await bot.get_file(doc.file_id)
    if LOCAL_API and f.file_path and os.path.isabs(f.file_path):
        dest.unlink(missing_ok=True)
        try:
            os.link(f.file_path, dest)
        except OSError:
            await asyncio.to_thread(shutil.copyfile, f.file_path, dest)
    else:
        await bot.download_file(f.file_path, destination=dest, timeout=900)


async def fetch(m: Message, dest: Path):
    doc = m.document
    if not LOCAL_API and doc.file_size and doc.file_size > 20 * 1024 * 1024:
        raise UserError(f"{E('bad')} فایلەکە گەورەترە لە 20MB")
    await save_doc(m.bot, doc, dest)


async def ask_prov(m: Message, state: FSMContext, pw, cert):
    cn, team = cert_names(cert)
    await state.update_data(
        pw=pw, der=cert.public_bytes(serialization.Encoding.DER).hex(),
        cn=cn, team=team, cexp=cert_exp(cert).isoformat())
    await state.set_state(C.prov)
    await m.answer(
        f"{E('ok')} <b>p12 دروستە</b>\n{E('user')} {escape(cn)} · <code>{escape(team)}</code>\n"
        f"{E('clock')} تا <code>{cert_exp(cert):%Y-%m-%d}</code>\n\n"
        f"{E('cert')} <b>هەنگاوی ٢/٢</b>\n{E('file')} ئێستا فایلی "
        f"<code>.mobileprovision</code> بنێرە",
        reply_markup=CANCEL)


@owner.message(C.p12, F.document)
async def got_p12(m: Message, state: FSMContext):
    name = (m.document.file_name or "").lower()
    if not name.endswith((".p12", ".pfx")):
        await m.answer(f"{E('bad')} تەنها فایلی <code>.p12</code> بنێرە", reply_markup=CANCEL)
        return
    p = udir(m.from_user.id) / "pending.p12"
    try:
        await fetch(m, p)
    except UserError as e:
        await m.answer(str(e), reply_markup=CANCEL)
        return
    res, cert = await asyncio.to_thread(read_p12, p, "")
    if res == "ok":                              # پاسۆردی نییە
        await ask_prov(m, state, "", cert)
    elif res == "pw":                            # پاسۆردی هەیە
        await state.set_state(C.pw)
        await m.answer(f"{E('key')} ئەم p12 پاسۆردی هەیە، پاسۆردەکە بنێرە",
                       reply_markup=CANCEL)
    else:
        p.unlink(missing_ok=True)
        await m.answer(f"{E('bad')} فایلەکە دروست نییە یان تێکچووە، p12ێکی تر بنێرە",
                       reply_markup=CANCEL)


@owner.message(C.p12)
async def p12_other(m: Message):
    await m.answer(f"{E('file')} فایلی <code>.p12</code> بنێرە", reply_markup=CANCEL)


@owner.message(C.pw, F.text)
async def got_pw(m: Message, state: FSMContext):
    pw = m.text.strip()
    try:
        await m.delete()                         # پاسۆرد لە چات بسڕەوە
    except Exception:
        pass
    p = udir(m.from_user.id) / "pending.p12"
    res, cert = await asyncio.to_thread(read_p12, p, pw)
    if res == "ok":
        await ask_prov(m, state, pw, cert)
    elif res == "pw":
        await m.answer(f"{E('bad')} <b>پاسۆردەکە هەڵەیە!</b>\n{E('key')} دووبارە پاسۆردی ڕاست بنێرە",
                       reply_markup=CANCEL)
    else:
        await m.answer(f"{E('bad')} فایلەکە تێکچووە، /start بکە و دووبارە بنێرە")
        await state.clear()


@owner.message(C.prov, F.document)
async def got_prov(m: Message, state: FSMContext):
    uid = m.from_user.id
    if not (m.document.file_name or "").lower().endswith(".mobileprovision"):
        await m.answer(f"{E('bad')} تەنها فایلی <code>.mobileprovision</code> بنێرە",
                       reply_markup=CANCEL)
        return
    d = udir(uid)
    pp = d / "pending.prov"
    try:
        await fetch(m, pp)
    except UserError as e:
        await m.answer(str(e), reply_markup=CANCEL)
        return
    prov = read_prov(pp)
    data = await state.get_data()
    err = None
    if not prov:
        err = "فایلەکە mobileprovisionی دروست نییە"
    elif prov.get("ExpirationDate") and prov["ExpirationDate"] < now_utc():
        err = "ئەم provision بەسەرچووە، نوێیەکە بنێرە"
    elif bytes.fromhex(data["der"]) not in prov.get("DeveloperCertificates", []):
        err = "ئەم provision بۆ ئەم p12 نییە (بروانامەکە تێیدا نییە)"
    elif not prov.get("ProvisionsAllDevices") and not prov.get("ProvisionedDevices"):
        err = "ئەمە provisionی App Storeـە و ناتوانرێت پێی دابمەزرێت"
    if err:
        pp.unlink(missing_ok=True)
        await m.answer(f"{E('bad')} <b>{err}</b>\n{E('file')} provisionێکی تر بنێرە",
                       reply_markup=CANCEL)
        return

    shutil.move(d / "pending.p12", d / "cert.p12")
    shutil.move(pp, d / "prov.mobileprovision")
    bundle = prov_bundle(prov)
    (d / "info.json").write_text(json.dumps({
        "cert": data["cn"], "team": data["team"], "cexp": data["cexp"],
        "prov": prov.get("Name", ""), "pexp": prov["ExpirationDate"].isoformat(),
        "bundle": bundle,
        "pw": FER.encrypt(data["pw"].encode()).decode() if data["pw"] else "",
    }), encoding="utf-8")
    os.chmod(d / "cert.p12", 0o600)
    await state.clear()
    ndev = len(prov.get("ProvisionedDevices", []))
    dev = f"{ndev} ئامێر" if ndev else "هەموو ئامێرەکان (Enterprise)"
    await m.answer(
        f"{E('ok')} <b>بڕوانامە داندرا!</b> {E('sparkle')}\n\n"
        f"{E('user')} {escape(data['cn'])}\n"
        f"{E('file')} {escape(prov.get('Name', ''))}\n"
        f"{E('phone')} {dev}\n"
        f"{E('ipa')} App ID: <code>{escape(bundle)}</code>\n\n"
        f"{E('bolt')} ئێستا دەتوانیت IPA واژۆ بکەیت",
        reply_markup=panel_kb())


@owner.message(C.prov)
async def prov_other(m: Message):
    await m.answer(f"{E('file')} فایلی <code>.mobileprovision</code> بنێرە", reply_markup=CANCEL)


# ───────── بەشی ٢: واژۆکردنی IPA ─────────
@owner.callback_query(F.data == "sign")
async def sign_start(c: CallbackQuery, state: FSMContext):
    if not uinfo(c.from_user.id):
        await c.answer("⚠️ سەرەتا بڕوانامە دابنێ", show_alert=True)
        return
    await c.answer()
    await state.set_state(G.ipa)
    await c.message.answer(f"{E('ipa')} فایلی <code>.ipa</code> بنێرە {E('bolt')}",
                           reply_markup=CANCEL)


@owner.message(G.ipa, F.document)
async def got_ipa(m: Message, state: FSMContext):
    uid = m.from_user.id
    doc = m.document
    if not (doc.file_name or "").lower().endswith(".ipa"):
        await m.answer(f"{E('bad')} تەنها فایلی <code>.ipa</code> بنێرە", reply_markup=CANCEL)
        return
    if not LOCAL_API and doc.file_size and doc.file_size > 20 * 1024 * 1024:
        await m.answer(f"{E('bad')} IPAکە گەورەترە لە 20MB (پێویستە LOCAL_API چالاک بکرێت)",
                       reply_markup=CANCEL)
        return
    await state.clear()
    st = await m.answer(f"{E('down')} <b>دادەبەزێت...</b>")
    work = WORK / uuid.uuid4().hex
    work.mkdir(parents=True)
    try:
        info = uinfo(uid)
        src = work / "in.ipa"
        await save_doc(m.bot, doc, src)

        pi = await asyncio.to_thread(ipa_info, src)
        if not pi:
            raise UserError("IPAکە دروست نییە (Info.plist نەدۆزرایەوە)")

        # لۆژیکی bundle id
        pb = info["bundle"]
        if pb.endswith("*"):                     # wildcard ← ناوی IPA دەمێنێتەوە
            if pb != "*" and not pi["id"].startswith(pb[:-1]):
                raise UserError(f"ناوی ئەپەکە <code>{escape(pi['id'])}</code> لەگەڵ provision "
                                f"<code>{escape(pb)}</code> ناگونجێت")
            force, final_id = None, pi["id"]
        else:                                    # ناوی provision سەپێنراو
            force, final_id = pb, pb

        if datetime.fromisoformat(info["pexp"]) < now_utc():
            raise UserError("provisionەکەت بەسەرچووە، نوێیەکە دابنێ")

        await st.edit_text(f"{E('sign')} <b>واژۆ دەکرێت...</b>")
        uid_dir = uuid.uuid4().hex
        dest = Path(WEBROOT) / uid_dir
        dest.mkdir(parents=True)
        ok, log = await run_zsign(uid, src, dest / "app.ipa", force)
        if not ok:
            shutil.rmtree(dest, ignore_errors=True)
            raise UserError(f"واژۆکردن سەرنەکەوت\n<code>{escape(log)}</code>")

        base = f"{DOMAIN}/apps/{uid_dir}"
        (dest / "manifest.plist").write_text(
            make_manifest(f"{base}/app.ipa", final_id, pi["ver"], pi["name"]), encoding="utf-8")
        link = f"itms-services://?action=download-manifest&url={base}/manifest.plist"
        (dest / "index.html").write_text(make_page(link, pi["name"]), encoding="utf-8")

        await st.edit_text(
            f"{E('ok')} <b>واژۆکرا!</b> {E('sparkle')}\n\n"
            f"{E('ipa')} {escape(pi['name'])} · <code>{escape(pi['ver'])}</code>\n"
            f"{E('id')} <code>{escape(final_id)}</code>\n"
            f"{E('clock')} لینکەکە {LINK_TTL // 60} خولەک کار دەکات\n\n"
            f"{E('phone')} دوگمەکە بکەرەوە لە <b>Safari</b> و Install بکە",
            reply_markup=kb([B("phone", "دامەزراندن", "success", url=f"{base}/")],
                            [B("sign", "IPAی تر", "primary", callback_data="sign")]))
    except UserError as e:
        await st.edit_text(f"{E('bad')} <b>{e}</b>", reply_markup=panel_kb())
    except Exception as e:
        await st.edit_text(f"{E('bad')} <b>هەڵەیەک ڕوویدا</b>\n<code>{escape(str(e))[:200]}</code>",
                           reply_markup=panel_kb())
    finally:
        shutil.rmtree(work, ignore_errors=True)


@owner.message(G.ipa)
async def ipa_other(m: Message):
    await m.answer(f"{E('ipa')} فایلی <code>.ipa</code> بنێرە", reply_markup=CANCEL)


# ───────── ڕێکخستنی ئیمۆجی (/setup) ─────────
async def ask(m: Message, state: FSMContext, i: int):
    if i >= len(KEYS):
        await state.clear()
        await m.answer(f"{E('ok')} <b>ئیمۆجییەکان تەواو بوون!</b> {E('sparkle')}\n/start بکە")
        return
    k = KEYS[i]
    await state.set_state(S.wait)
    await state.update_data(i=i)
    await m.answer(
        f"<b>{i + 1}/{len(KEYS)}</b>\n{SLOTS[k][0]} <b>{SLOTS[k][1]}</b>\n"
        f"ئیمۆجی پریمیۆمێک بنێرە بۆ ئێرە",
        reply_markup=kb([B("skip", "بازدان", "danger", callback_data="skip")]))


@owner.message(Command("setup"))
async def setup_cmd(m: Message, state: FSMContext):
    if m.from_user.id != OWNER_ID:
        return
    await ask(m, state, 0)


@owner.callback_query(F.data == "skip", S.wait)
async def skip(c: CallbackQuery, state: FSMContext):
    await c.answer()
    i = (await state.get_data())["i"]
    await ask(c.message, state, i + 1)


@owner.message(S.wait)
async def got_emoji(m: Message, state: FSMContext):
    ents = [e for e in (m.entities or []) if e.type == "custom_emoji"]
    if not ents:
        await m.answer("تەنها ئیمۆجی پریمیۆم بنێرە ☝️")
        return
    i = (await state.get_data())["i"]
    IDS[KEYS[i]] = ents[0].custom_emoji_id
    save_ids()
    await ask(m, state, i + 1)


# ───────── سڕینەوەی لینکە کۆنەکان ─────────
async def cleaner():
    while True:
        try:
            now = time.time()
            for p in Path(WEBROOT).glob("*"):
                if p.is_dir() and now - p.stat().st_mtime > LINK_TTL:
                    shutil.rmtree(p, ignore_errors=True)
        except Exception:
            pass
        await asyncio.sleep(600)


# ───────── سێرڤەری وێب (بۆ لینکی دامەزراندن) ─────────
async def page(request):
    uid = request.match_info["id"]
    if not re.fullmatch(r"[0-9a-f]{32}", uid):
        raise web.HTTPNotFound()
    f = Path(WEBROOT) / uid / "index.html"
    if not f.exists():
        raise web.HTTPNotFound()
    return web.FileResponse(f)


async def start_web():
    app = web.Application()
    app.router.add_get("/", lambda r: web.Response(text="OK"))
    app.router.add_get("/apps/{id}/", page)
    app.router.add_static("/apps", WEBROOT, show_index=False)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start()


async def main():
    for tool in ("zsign", "openssl"):
        if not shutil.which(tool):
            print(f"⚠️ {tool} نەدۆزرایەوە! دابمەزرێنە.")
    Path(WEBROOT).mkdir(parents=True, exist_ok=True)
    session = (AiohttpSession(api=TelegramAPIServer.from_base(LOCAL_API, is_local=True))
               if LOCAL_API else None)
    bot = Bot(TOKEN, session=session, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()
    dp.include_router(owner)
    dp.include_router(guest)
    await start_web()
    asyncio.create_task(cleaner())
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
