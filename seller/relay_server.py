# -*- coding: utf-8 -*-
"""
السيرفر الوسيط + نظام التراخيص — يشتغل على سيرفرك أنت (مو عند المشتري).

- المشتري يفعّل من جواله: كود الترخيص -> رمز تحقق على جواله/إيميله المسجّل -> يختار PIN.
- الـ agent على كمبيوتره يرتبط بالترخيص أول مرة (بصمة الجهاز) وما يشتغل على جهاز ثاني.
- الجوال مربوط بتوكن سري محفوظ عنده + PIN، وجوال واحد فقط في نفس الوقت.

التشغيل:  python relay_server.py
"""

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from collections import defaultdict

from aiohttp import web, WSMsgType

import licensedb as ldb
import otp as otpmod

PORT = int(os.environ.get("PORT", "8080"))
ENFORCE_INTERVAL = float(os.environ.get("ENFORCE_INTERVAL", "30"))
BASE_DIR = (
    os.path.dirname(sys.executable)
    if getattr(sys, "frozen", False)
    else os.path.dirname(os.path.abspath(__file__))
)

OTP_TTL = 600            # صلاحية الرمز: 10 دقائق
OTP_MAX_ATTEMPTS = 5     # محاولات إدخال الرمز
OTP_COOLDOWN = 60        # بين كل طلب رمز وطلب
OTP_MAX_PER_HOUR = 5     # أقصى عدد رموز بالساعة لكل ترخيص
AUTH_FAIL_LIMIT = 5      # محاولات دخول خاطئة لكل ترخيص قبل القفل
AUTH_LOCK_SECONDS = 900  # مدة القفل: 15 دقيقة

rooms = {}        # code -> {"agent": ws|None, "control": ws|None, "pending": ws|None}
ws_info = {}      # ws -> (code, role)
otp_state = {}    # code -> {"sent": [], "hash": None, "exp": 0, "attempts": 0}
buckets = defaultdict(list)   # (name, key) -> [timestamps]
auth_fails = defaultdict(list)  # code -> [timestamps]


# ---------------------------------------------------------------- أدوات مساعدة
def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def over(name, key, limit, window):
    t = time.time()
    lst = [x for x in buckets[(name, key)] if t - x < window]
    buckets[(name, key)] = lst
    return len(lst) >= limit


def record(name, key):
    buckets[(name, key)].append(time.time())


def client_ip(request):
    # نثق بهيدر Cloudflare فقط لو الاتصال جاي من النفق المحلي
    if request.remote in ("127.0.0.1", "::1"):
        fwd = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote or "unknown"


def locked(code):
    t = time.time()
    auth_fails[code] = [x for x in auth_fails[code] if t - x < AUTH_LOCK_SECONDS]
    return len(auth_fails[code]) >= AUTH_FAIL_LIMIT


async def safe_send(ws, data):
    try:
        await ws.send_json(data)
    except Exception:
        pass


async def safe_close(ws):
    try:
        await ws.close()
    except Exception:
        pass


# ---------------------------------------------------------------- تفعيل الجوال
SIGNUP_MODE = os.environ.get("SIGNUP_MODE", "approval").strip().lower()  # approval | open
signups = {}   # contact -> حالة رمز التسجيل
setups = {}    # setup_token -> {"code","secret","exp"} (إنشاء اسم المستخدم بعد التحقق)


def reply(ws, type_, **kw):
    return safe_send(ws, {"type": type_, **kw})


def fail(ws, type_, reason, **kw):
    return safe_send(ws, {"type": type_, "ok": False, "reason": reason, **kw})


async def issue_otp(st, channel, contact, code_for_limits=None):
    """يرسل رمز تحقق مع حدود (تبريد/ساعة). يرجّع (otp, سبب_خطأ, ثواني_انتظار)."""
    t = time.time()
    st["sent"] = [x for x in st["sent"] if t - x < 3600]
    if st["sent"] and t - st["sent"][-1] < OTP_COOLDOWN:
        return None, "cooldown", int(OTP_COOLDOWN - (t - st["sent"][-1])) + 1
    if len(st["sent"]) >= OTP_MAX_PER_HOUR:
        return None, "too_many_codes", 0
    otp = f"{secrets.randbelow(10 ** 6):06d}"
    try:
        await otpmod.send_otp(channel, contact, otp)
    except Exception as e:
        print("[OTP] فشل الإرسال:", e, flush=True)
        return None, "send_failed", 0
    st["sent"].append(t)
    return otp, None, 0


def check_otp(st, key, otp):
    """يتحقق من الرمز. يرجّع None لو صح أو سبب الرفض."""
    now = time.time()

    print(
        "[OTP DEBUG]",
        "state_exists:", bool(st),
        "hash_exists:", bool(st and st.get("hash")),
        "now:", now,
        "exp:", st.get("exp") if st else None,
        "remaining:", (st["exp"] - now) if st else None,
        flush=True
    )

    if not st or not st.get("hash") or now > st["exp"]:
        return "otp_expired"

    st["attempts"] += 1

    if st["attempts"] > OTP_MAX_ATTEMPTS:
        st["hash"] = None
        return "too_many_attempts"

    if not hmac.compare_digest(_h(key + str(otp)), st["hash"]):
        return "wrong_otp"

    return None


# ---------------------------------------------------------------- التسجيل (جوال/إيميل + رقم سري + رمز)
async def on_signup_start(ws, ip, msg):
    if over("fail", ip, 15, 600) or over("signup", ip, 10, 3600):
        return await fail(ws, "signup_result", "rate_limited")
    parsed = ldb.parse_contact(msg.get("contact"))
    if not parsed:
        return await fail(ws, "signup_result", "bad_contact")
    secret = str(msg.get("secret", "")).strip()
    if not re.fullmatch(r"\d{6}", secret):
        return await fail(ws, "signup_result", "bad_secret_format")
    channel, contact = parsed
    existing = ldb.get_by_contact(contact)
    if existing and existing.get("username"):
        return await fail(ws, "signup_result", "exists")
    record("signup", ip)
    st = signups.setdefault(contact, {"sent": [], "hash": None, "exp": 0, "attempts": 0})
    otp, why, wait = await issue_otp(st, channel, contact)
    if why:
        return await fail(ws, "signup_result", why, wait=wait)
    st.update(hash=_h(contact + otp), exp=time.time() + OTP_TTL, attempts=0, secret=secret, channel=channel)
    await reply(ws, "otp_sent", masked=ldb.mask_contact(channel, contact))


async def on_signup_verify(ws, ip, msg):
    parsed = ldb.parse_contact(msg.get("contact"))
    if not parsed:
        return await fail(ws, "signup_result", "bad_contact")
    channel, contact = parsed
    st = signups.get(contact)
    why = check_otp(st, contact, str(msg.get("otp", "")).strip())
    if why:
        if why == "wrong_otp":
            record("fail", ip)
        return await fail(ws, "signup_result", why)
    existing = ldb.get_by_contact(contact)
    if existing and existing.get("username"):
        return await fail(ws, "signup_result", "exists")
    code = existing["code"] if existing else ldb.create_license(channel, contact, "self-signup")
    ldb.set_status(code, "active" if SIGNUP_MODE == "open" else "pending")
    token = secrets.token_urlsafe(24)
    setups[token] = {"code": code, "secret": st["secret"], "exp": time.time() + 900}
    st["hash"] = None
    await reply(ws, "signup_verified", setup_token=token)


async def on_set_credentials(ws, ip, msg):
    s = setups.get(str(msg.get("setup_token", "")))
    if not s or time.time() > s["exp"]:
        return await fail(ws, "signup_result", "setup_expired")
    username = ldb.normalize_username(msg.get("username"))
    password = str(msg.get("password", ""))
    if not username:
        return await fail(ws, "signup_result", "bad_username")
    if not 8 <= len(password) <= 72:
        return await fail(ws, "signup_result", "bad_password")
    res = ldb.set_credentials(s["code"], username, password)
    if res != "ok":
        return await fail(ws, "signup_result", "username_taken" if res == "taken" else "exists")
    token = secrets.token_urlsafe(32)
    ldb.bind_phone(s["code"], token, s["secret"])   # الرقم السري = بصمة الجوال الثانية
    setups.pop(str(msg.get("setup_token")), None)
    row = ldb.get_license(s["code"])
    await reply(ws, "account_ready", ok=True, username=username, token=token, status=row["status"])


# ---------------------------------------------------------------- دخول الجوال
def session_of(ws, role=None):
    info = ws_info.get(ws)
    return info if info and (role is None or info[1] == role) else None


async def start_session(ws, row, new_token=None):
    """الجوال دخل بحسابه: يظهر له جهازه (متصل/غير متصل) قبل ما يوصّل."""
    code = row["code"]
    r = rooms.setdefault(code, {"agent": None, "control": None, "pending": None})
    old = r.get("pending")
    if old and old is not ws:
        await safe_send(old, {"type": "kicked"})
        await safe_close(old)
    await kick_control(code, except_ws=ws)
    r["pending"] = ws
    ws_info[ws] = (code, "authed")
    extra = {"token": new_token} if new_token else {}
    await reply(ws, "login_ok", ok=True, username=row["username"],
                pc={"online": bool(r.get("agent")), "name": row.get("agent_name") or ""}, **extra)


async def on_login(ws, ip, msg):
    if over("fail", ip, 15, 600):
        return await fail(ws, "login_result", "rate_limited")

    row = ldb.get_by_username(
        ldb.normalize_username(msg.get("username")) or ""
    )

    print("[LOGIN DEBUG] username_valid:",
          bool(ldb.normalize_username(msg.get("username"))), flush=True)
    print("[LOGIN DEBUG] account_found:", bool(row), flush=True)
    print("[LOGIN DEBUG] password_hash_exists:",
          bool(row and row.get("pw_hash")), flush=True)
    print("[LOGIN DEBUG] password_matches:",
      ldb.check_password(row, msg.get("password", "")), flush=True)

    code = row and row["code"]

    if code and locked(code):
        return await fail(ws, "login_result", "locked")

    if not ldb.check_password(row, msg.get("password", "")):
        record("fail", ip)
        if code:
            auth_fails[code].append(time.time())
        return await fail(ws, "login_result", "bad_credentials")

    ok, reason = ldb.usable(row)
    if not ok:
        return await fail(ws, "login_result", reason)

    if ldb.check_token(row, str(msg.get("token", ""))):
        return await start_session(ws, row)

    if row["phone_binds"] >= ldb.MAX_PHONE_BINDS:
        return await fail(ws, "login_result", "rebind_limit")

    if over("start", ip, 10, 3600):
        return await fail(ws, "login_result", "rate_limited")

    record("start", ip)
    st = otp_state.setdefault(code, {"sent": [], "hash": None, "exp": 0, "attempts": 0})
    otp, why, wait = await issue_otp(st, row["channel"], row["contact"])
    if why:
        return await fail(ws, "login_result", why, wait=wait)

    st.update(hash=_h(code + otp), exp=time.time() + OTP_TTL, attempts=0)
    await reply(ws, "need_otp", masked=ldb.mask_contact(row["channel"], row["contact"]))


async def on_login_verify(ws, ip, msg):
    if over("fail", ip, 15, 600):
        return await fail(ws, "login_result", "rate_limited")
    row = ldb.get_by_username(ldb.normalize_username(msg.get("username")) or "")
    code = row and row["code"]
    if code and locked(code):
        return await fail(ws, "login_result", "locked")
    secret = str(msg.get("secret", "")).strip()
    if not ldb.check_password(row, msg.get("password", "")):
        record("fail", ip)
        if code:
            auth_fails[code].append(time.time())
        return await fail(ws, "login_result", "bad_credentials")
    ok, reason = ldb.usable(row)
    if not ok:
        return await fail(ws, "login_result", reason)
    why = check_otp(otp_state.get(code), code, str(msg.get("otp", "")).strip())
    if why:
        if why == "wrong_otp":
            record("fail", ip)
        return await fail(ws, "login_result", why)
    if not ldb.check_pin(row, secret):
        record("fail", ip)
        auth_fails[code].append(time.time())
        return await fail(ws, "login_result", "bad_secret")
    token = secrets.token_urlsafe(32)
    res = ldb.bind_phone(code, token, secret)
    if res != "ok":
        return await fail(ws, "login_result", res)
    otp_state[code]["hash"] = None
    await start_session(ws, ldb.get_license(code), new_token=token)


async def on_connect_pc(ws, ip, msg):
    info = session_of(ws, "authed")
    if not info:
        return await fail(ws, "auth_result", "bad_credentials")
    code = info[0]
    r = rooms.get(code)
    if not r or not r.get("agent"):
        return await fail(ws, "auth_result", "agent_offline")
    r["pending"] = None
    await kick_control(code, except_ws=ws)
    r["control"] = ws
    ws_info[ws] = (code, "control")
    await safe_send(r["agent"], {"type": "controller", "connected": True})
    await reply(ws, "auth_result", ok=True)


async def on_pc_status(ws, ip, msg):
    info = session_of(ws, "authed")
    if info:
        r = rooms.get(info[0]) or {}
        row = ldb.get_license(info[0]) or {}
        await reply(ws, "pc_status", online=bool(r.get("agent")), name=row.get("agent_name") or "")


async def kick_control(code, except_ws=None):
    r = rooms.get(code)
    old = r.get("control") if r else None
    if old and old is not except_ws:
        r["control"] = None
        await safe_send(old, {"type": "kicked"})
        await safe_close(old)


# ---------------------------------------------------------------- تسجيل الـ agent
async def on_register_agent(ws, ip, msg):
    hwid = str(msg.get("hwid", ""))[:200]
    name = str(msg.get("name", ""))[:60]

    def deny(reason):
        return safe_send(ws, {"type": "registered_agent", "ok": False, "reason": reason})

    if over("fail", ip, 15, 600):
        return await deny("rate_limited")
    row = ldb.get_by_username(ldb.normalize_username(msg.get("username")) or "")
    code = row and row["code"]
    if not row or not hwid:
        record("fail", ip)
        return await deny("bad_credentials")
    if locked(code):
        return await deny("locked")
    by_token = ldb.check_agent_token(row, msg.get("agent_token", ""))
    if not (by_token or ldb.check_password(row, msg.get("password", ""))):
        record("fail", ip)
        auth_fails[code].append(time.time())
        return await deny("bad_credentials")
    ok, reason = ldb.usable(row)
    if not ok:
        return await deny(reason)
    bound, why = ldb.bind_agent(code, _h("hw:" + hwid))
    if not bound:
        record("fail", ip)
        return await deny(why)
    ldb.set_agent_info(code, ip, name)
    new_token = None
    if not by_token:  # أول دخول بكلمة المرور: نعطي الجهاز مفتاح يحفظه بدل كلمة المرور
        new_token = secrets.token_urlsafe(32)
        ldb.set_agent_token(code, new_token)

    r = rooms.setdefault(code, {"agent": None, "control": None, "pending": None})
    old = r.get("agent")
    if old and old is not ws:
        await safe_close(old)
    r["agent"] = ws
    ws_info[ws] = (code, "agent")
    await safe_send(ws, {"type": "registered_agent", "ok": True, "agent_token": new_token})
    for w in (r.get("control"), r.get("pending")):
        if w:
            await safe_send(w, {"type": "agent_online", "name": name})


async def cleanup(ws):
    info = ws_info.pop(ws, None)
    if not info:
        return
    code, role = info
    r = rooms.get(code)
    if not r:
        return
    if role == "agent" and r.get("agent") is ws:
        r["agent"] = None
        for w in (r.get("control"), r.get("pending")):
            if w:
                await safe_send(w, {"type": "agent_offline"})
    elif role == "authed" and r.get("pending") is ws:
        r["pending"] = None
    elif role == "control" and r.get("control") is ws:
        r["control"] = None
        if r.get("agent"):
            await safe_send(r["agent"], {"type": "stream", "on": False})
            await safe_send(r["agent"], {"type": "controller", "connected": False})


async def forward(ws, msg):
    info = ws_info.get(ws)
    if not info:
        return
    code, role = info
    r = rooms.get(code)
    if not r:
        return
    if role == "control" and r.get("agent"):
        await safe_send(r["agent"], msg)
    elif role == "agent" and r.get("control") and msg.get("type") == "frame":
        await safe_send(r["control"], msg)


HANDLERS = {
    "signup_start": on_signup_start,
    "signup_verify": on_signup_verify,
    "set_credentials": on_set_credentials,
    "login": on_login,
    "login_verify": on_login_verify,
    "connect_pc": on_connect_pc,
    "pc_status": on_pc_status,
    "register_agent": on_register_agent,
}


async def ws_handler(request):
    ws = web.WebSocketResponse(heartbeat=20, max_msg_size=4 * 1024 * 1024)
    await ws.prepare(request)
    ip = client_ip(request)
    try:
        async for raw in ws:
            if raw.type != WSMsgType.TEXT:
                continue
            try:
                msg = json.loads(raw.data)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict):
                continue
            handler = HANDLERS.get(msg.get("type"))
            if handler:
                await handler(ws, ip, msg)
            else:
                await forward(ws, msg)
    finally:
        await cleanup(ws)
    return ws


# ---------------------------------------------------------------- فرض الترخيص (إيقاف/انتهاء/فك ربط)
async def enforcer():
    while True:
        await asyncio.sleep(ENFORCE_INTERVAL)
        for code, r in list(rooms.items()):
            row = ldb.get_license(code)
            ok = bool(row) and ldb.usable(row)[0] and bool(row["phone_token_hash"])
            if ok:
                continue
            targets = [w for w in (r.get("agent"), r.get("control"), r.get("pending")) if w]
            for w in targets:  # نبلّغ الكل أول، بعدين نقفل (عشان يوصلهم السبب قبل الفصل)
                await safe_send(w, {"type": "license_ended"})
            for w in targets:
                await safe_close(w)


async def background(app):
    task = asyncio.create_task(enforcer())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------- الملفات الثابتة
NO_CACHE = {"Cache-Control": "no-cache"}


async def index(request):
    return web.FileResponse(os.path.join(BASE_DIR, "control.html"), headers=NO_CACHE)


async def asset(request):
    path = os.path.join(BASE_DIR, os.path.basename(request.path))
    if not os.path.isfile(path):
        raise web.HTTPNotFound()
    return web.FileResponse(path, headers=NO_CACHE)


async def health(request):
    return web.json_response({"ok": True})


ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()


async def admin_run(request):
    """إدارة التراخيص عن بعد (للاستضافة بدون وصول للسيرفر). مقفولة إلا لو ضبطت ADMIN_TOKEN."""
    if len(ADMIN_TOKEN) < 16:
        return web.json_response({"ok": False, "error": "disabled"}, status=404)
    ip = client_ip(request)
    if over("admin_fail", ip, 5, 900):
        return web.json_response({"ok": False, "error": "rate_limited"}, status=429)
    auth = request.headers.get("Authorization", "")
    if not hmac.compare_digest(auth.encode(), ("Bearer " + ADMIN_TOKEN).encode()):
        record("admin_fail", ip)
        return web.json_response({"ok": False, "error": "unauthorized"}, status=401)
    try:
        args = (await request.json()).get("args")
        assert isinstance(args, list) and all(isinstance(a, str) for a in args) and len(args) < 20
    except Exception:
        return web.json_response({"ok": False, "error": "bad_request"}, status=400)
    here = os.path.dirname(os.path.abspath(__file__))
    proc = await asyncio.create_subprocess_exec(
        sys.executable, os.path.join(here, "admin.py"), *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env={**os.environ, "RC_ADMIN_URL": ""},
    )
    out, _ = await asyncio.wait_for(proc.communicate(), 20)
    return web.json_response({"ok": proc.returncode == 0, "output": out.decode("utf-8", "replace")})

# ---------------------------------------------------------------- لوحة البائع الخاصة

SELLER_USERNAME = os.environ.get("SELLER_USERNAME", "").strip()
SELLER_PASSWORD = os.environ.get("SELLER_PASSWORD", "").strip()


def seller_authorized(request):
    if len(SELLER_PASSWORD) < 16 or not SELLER_USERNAME:
        return False

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False

    import base64
    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        return False

    return (
        hmac.compare_digest(username, SELLER_USERNAME)
        and hmac.compare_digest(password, SELLER_PASSWORD)
    )


def seller_auth_required(request):
    if not seller_authorized(request):
        raise web.HTTPUnauthorized(
            headers={"WWW-Authenticate": 'Basic realm="Seller Panel"'}
        )


def seller_check_origin(request):
    origin = request.headers.get("Origin", "")
    if not origin or origin.split("://", 1)[-1].rstrip("/") != request.host:
        raise web.HTTPForbidden(text="Invalid origin")


def seller_status(row):
    ok, reason = ldb.usable(row)
    if ok:
        return "active"
    return reason or "inactive"


async def seller_page(request):
    seller_auth_required(request)
    return web.FileResponse(
        os.path.join(BASE_DIR, "seller.html"),
        headers={"Cache-Control": "no-store"}
    )


async def seller_list(request):
    seller_auth_required(request)

    try:
        rows = ldb.list_licenses()
        result = []

        for r in rows:
            result.append({
                "code": r["code"],
                "username": r.get("username") or "بدون اسم",
                "status": seller_status(r),
                "contact": ldb.mask_contact(
                    r.get("channel", ""),
                    r.get("contact", "")
                ),
                "created_at": r.get("created_at"),
                "expires_at": r.get("expires_at"),
                "agent_online": bool(
                    rooms.get(r["code"], {}).get("agent")
                )
            })

        return web.json_response({"ok": True, "licenses": result})

    except Exception as e:
        print("[SELLER] list error:", e, flush=True)
        return web.json_response(
            {"ok": False, "error": "database_error"},
            status=500
        )


async def seller_activate(request):
    seller_auth_required(request)
    seller_check_origin(request)

    code = ldb.normalize_code(request.match_info["code"])
    if not code:
        return web.json_response({"ok": False, "error": "bad_code"}, status=400)

    row = ldb.get_license(code)
    if not row:
        return web.json_response({"ok": False, "error": "not_found"}, status=404)

    try:
        data = await request.json()
        days = int(data.get("days", 30))
        if not 1 <= days <= 3650:
            raise ValueError
    except Exception:
        return web.json_response({"ok": False, "error": "invalid_days"}, status=400)

    expires = int(time.time()) + days * 86400

    with ldb.db() as c:
        c.execute(
            "UPDATE licenses SET status='active', expires_at=%s WHERE code=%s",
            (expires, code)
        )

    return web.json_response({"ok": True, "expires_at": expires})


async def seller_revoke(request):
    seller_auth_required(request)
    seller_check_origin(request)

    code = ldb.normalize_code(request.match_info["code"])
    if not code:
        return web.json_response({"ok": False, "error": "bad_code"}, status=400)

    if not ldb.get_license(code):
        return web.json_response({"ok": False, "error": "not_found"}, status=404)

    ldb.set_status(code, "revoked")

    return web.json_response({"ok": True})


async def seller_extend(request):
    seller_auth_required(request)
    seller_check_origin(request)

    code = ldb.normalize_code(request.match_info["code"])
    if not code:
        return web.json_response({"ok": False, "error": "bad_code"}, status=400)

    row = ldb.get_license(code)
    if not row:
        return web.json_response({"ok": False, "error": "not_found"}, status=404)

    try:
        data = await request.json()
        days = int(data.get("days", 30))
        if not 1 <= days <= 3650:
            raise ValueError
    except Exception:
        return web.json_response({"ok": False, "error": "invalid_days"}, status=400)

    base = max(int(time.time()), row.get("expires_at") or 0)
    expires = base + days * 86400

    with ldb.db() as c:
        c.execute(
            "UPDATE licenses SET expires_at=%s, status='active' WHERE code=%s",
            (expires, code)
        )

    return web.json_response({"ok": True, "expires_at": expires})
def make_app():
    app = web.Application()

    # إدارة التراخيص القديمة
    app.router.add_post("/admin/run", admin_run)

    # لوحة البائع
    app.router.add_get("/seller", seller_page)
    app.router.add_get("/seller/", seller_page)
    app.router.add_get("/seller/api/licenses", seller_list)
    app.router.add_post("/seller/api/licenses/{code}/activate", seller_activate)
    app.router.add_post("/seller/api/licenses/{code}/revoke", seller_revoke)
    app.router.add_post("/seller/api/licenses/{code}/extend", seller_extend)

    # واجهة العميل
    app.router.add_get("/", index)
    app.router.add_get("/control.html", index)

    for name in (
    "manifest.json", "sw.js",
    "icon-192.png", "icon-512.png",
    "icon-512-maskable.png",
    "seller.css", "seller.js"
):
        app.router.add_get("/" + name, asset)

    app.router.add_get("/health", health)
    app.router.add_get("/ws", ws_handler)

    app.cleanup_ctx.append(background)
    return app


def main():
    ldb.init_db()
    print("=" * 56)
    print("  السيرفر الوسيط + التراخيص شغّال ✅")
    print("=" * 56)
    print(f"  المنفذ: {PORT}")
    print(f"  إرسال الرموز: {otpmod.describe()}")
    print(f"  وضع التسجيل: {SIGNUP_MODE}  (approval = الحساب ينتظر تفعيلك بعد الدفع | open = فوري)")
    if otpmod.is_dev_mode():
        print("  ⚠️ وضع تجربة: الرمز يطبع هنا بدل ما يوصل للمشتري (راجع otp.py)")
    print("  إدارة التراخيص: python admin.py --help")
    print("=" * 56, flush=True)
    web.run_app(make_app(), host=os.environ.get("HOST", "0.0.0.0"), port=PORT, print=None)


if __name__ == "__main__":
    main()
