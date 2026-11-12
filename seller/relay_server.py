
# -*- coding: utf-8 -*-
"""
السيرفر الوسيط + نظام التراخيص — يشتغل على سيرفرك أنت (مو عند المشتري).

- المشتري يفعّل من جواله: كود الترخيص -> رمز تحقق -> PIN.
- الـ Agent يرتبط بالترخيص وبصمة الجهاز.
- الجوال يستخدم توكن سري محفوظ لتسجيل الدخول تلقائياً.
- جوال واحد فقط في نفس الوقت.
- دعم الصوت المباشر من الكمبيوتر إلى الجوال.
- دعم اكتشاف الشاشات المتعددة والتنقل بينها.

التشغيل: python relay_server.py
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
from urllib.parse import urlparse

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

OTP_TTL = 600
OTP_MAX_ATTEMPTS = 5
OTP_COOLDOWN = 60
OTP_MAX_PER_HOUR = 5

AUTH_FAIL_LIMIT = 5
AUTH_LOCK_SECONDS = 900

rooms = {}
ws_info = {}
otp_state = {}

pending_pairs = {}
PAIR_TTL = 600

buckets = defaultdict(list)
auth_fails = defaultdict(list)


# ----------------------------------------------------------------
# أدوات مساعدة
# ----------------------------------------------------------------

def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def over(name, key, limit, window):
    t = time.time()
    lst = [x for x in buckets[(name, key)] if t - x < window]
    buckets[(name, key)] = lst
    return len(lst) >= limit


def record(name, key):
    buckets[(name, key)].append(time.time())


TRUST_PROXY = os.environ.get("TRUST_PROXY", "").strip().lower()


def client_ip(request):
    if request.remote in ("127.0.0.1", "::1"):
        fwd = (
            request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Forwarded-For", "")
        )
        if fwd:
            return fwd.split(",")[0].strip()

    elif TRUST_PROXY == "cf":
        v = request.headers.get("CF-Connecting-IP", "").strip()
        if v:
            return v

    elif TRUST_PROXY == "xff":
        parts = [
            x.strip()
            for x in request.headers.get("X-Forwarded-For", "").split(",")
            if x.strip()
        ]
        if parts:
            return parts[-1]

    return request.remote or "unknown"


def locked(code):
    t = time.time()
    auth_fails[code] = [
        x for x in auth_fails[code]
        if t - x < AUTH_LOCK_SECONDS
    ]
    return len(auth_fails[code]) >= AUTH_FAIL_LIMIT


async def safe_send(ws, data):
    try:
        if ws and not ws.closed:
            await ws.send_json(data)
    except Exception:
        pass


async def safe_close(ws):
    try:
        if ws and not ws.closed:
            await ws.close()
    except Exception:
        pass


# ----------------------------------------------------------------
# تفعيل الجوال
# ----------------------------------------------------------------

SIGNUP_MODE = os.environ.get(
    "SIGNUP_MODE", "approval"
).strip().lower()

signups = {}
setups = {}


def reply(ws, type_, **kw):
    return safe_send(ws, {"type": type_, **kw})


def fail(ws, type_, reason, **kw):
    return safe_send(
        ws,
        {"type": type_, "ok": False, "reason": reason, **kw}
    )


async def issue_otp(st, channel, contact, code_for_limits=None):
    t = time.time()

    st["sent"] = [
        x for x in st["sent"]
        if t - x < 3600
    ]

    if st["sent"] and t - st["sent"][-1] < OTP_COOLDOWN:
        wait = int(OTP_COOLDOWN - (t - st["sent"][-1])) + 1
        return None, "cooldown", wait

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
    if not st or not st.get("hash") or time.time() > st["exp"]:
        return "otp_expired"

    st["attempts"] += 1

    if st["attempts"] > OTP_MAX_ATTEMPTS:
        st["hash"] = None
        return "too_many_attempts"

    if not hmac.compare_digest(_h(key + str(otp)), st["hash"]):
        return "wrong_otp"

    return None


# ----------------------------------------------------------------
# التسجيل
# ----------------------------------------------------------------

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

    st = signups.setdefault(
        contact,
        {
            "sent": [],
            "hash": None,
            "exp": 0,
            "attempts": 0
        }
    )

    otp, why, wait = await issue_otp(st, channel, contact)

    if why:
        return await fail(
            ws, "signup_result", why, wait=wait
        )

    st.update(
        hash=_h(contact + otp),
        exp=time.time() + OTP_TTL,
        attempts=0,
        secret=secret,
        channel=channel
    )

    await reply(
        ws,
        "otp_sent",
        masked=ldb.mask_contact(channel, contact)
    )


async def on_signup_verify(ws, ip, msg):
    parsed = ldb.parse_contact(msg.get("contact"))

    if not parsed:
        return await fail(ws, "signup_result", "bad_contact")

    channel, contact = parsed
    st = signups.get(contact)

    why = check_otp(
        st,
        contact,
        str(msg.get("otp", "")).strip()
    )

    if why:
        if why == "wrong_otp":
            record("fail", ip)

        return await fail(ws, "signup_result", why)

    existing = ldb.get_by_contact(contact)

    if existing and existing.get("username"):
        return await fail(ws, "signup_result", "exists")

    code = (
        existing["code"]
        if existing
        else ldb.create_license(
            channel,
            contact,
            "self-signup"
        )
    )

    ldb.set_status(
        code,
        "active" if SIGNUP_MODE == "open" else "pending"
    )

    token = secrets.token_urlsafe(24)

    setups[token] = {
        "code": code,
        "secret": st["secret"],
        "exp": time.time() + 900
    }

    st["hash"] = None

    await reply(
        ws,
        "signup_verified",
        setup_token=token
    )


async def on_set_credentials(ws, ip, msg):
    setup_token = str(msg.get("setup_token", ""))
    s = setups.get(setup_token)

    if not s or time.time() > s["exp"]:
        return await fail(ws, "signup_result", "setup_expired")

    username = ldb.normalize_username(msg.get("username"))
    password = str(msg.get("password", ""))

    if not username:
        return await fail(ws, "signup_result", "bad_username")

    if not 8 <= len(password) <= 72:
        return await fail(ws, "signup_result", "bad_password")

    res = ldb.set_credentials(
        s["code"],
        username,
        password
    )

    if res != "ok":
        reason = "username_taken" if res == "taken" else "exists"
        return await fail(ws, "signup_result", reason)

    token = secrets.token_urlsafe(32)

    ldb.bind_phone(
        s["code"],
        token,
        s["secret"]
    )

    setups.pop(setup_token, None)

    row = ldb.get_license(s["code"])

    await reply(
        ws,
        "account_ready",
        ok=True,
        username=username,
        token=token,
        status=row["status"]
    )


# ----------------------------------------------------------------
# دخول الجوال والجلسات
# ----------------------------------------------------------------

def session_of(ws, role=None):
    info = ws_info.get(ws)

    return (
        info
        if info and (role is None or info[1] == role)
        else None
    )


async def start_session(ws, row, new_token=None):
    code = row["code"]

    r = rooms.setdefault(
        code,
        {
            "agent": None,
            "control": None,
            "pending": None
        }
    )

    old = r.get("pending")

    if old and old is not ws:
        await safe_send(old, {"type": "kicked"})
        await safe_close(old)

    await kick_control(code, except_ws=ws)

    r["pending"] = ws
    ws_info[ws] = (code, "authed")

    extra = {"token": new_token} if new_token else {}

    await reply(
        ws,
        "login_ok",
        ok=True,
        username=row["username"],
        pc={
            "online": bool(r.get("agent")),
            "name": row.get("agent_name") or ""
        },
        **extra
    )


async def on_login(ws, ip, msg):
    if over("fail", ip, 15, 600):
        return await fail(ws, "login_result", "rate_limited")

    row = ldb.get_by_username(
        ldb.normalize_username(msg.get("username")) or ""
    )

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

    st = otp_state.setdefault(
        code,
        {
            "sent": [],
            "hash": None,
            "exp": 0,
            "attempts": 0
        }
    )

    otp, why, wait = await issue_otp(
        st,
        row["channel"],
        row["contact"]
    )

    if why:
        return await fail(
            ws, "login_result", why, wait=wait
        )

    st.update(
        hash=_h(code + otp),
        exp=time.time() + OTP_TTL,
        attempts=0
    )

    await reply(
        ws,
        "need_otp",
        masked=ldb.mask_contact(
            row["channel"],
            row["contact"]
        )
    )


# ----------------------------------------------------------------
# تسجيل الدخول التلقائي بالتوكن
# ----------------------------------------------------------------

async def on_resume_login(ws, ip, msg):
    """
    استعادة جلسة الجوال باستخدام التوكن المحفوظ فقط.
    لا يطلب كلمة المرور أو OTP عند كل زيارة.
    """

    if over("fail", ip, 15, 600):
        return await fail(
            ws,
            "login_result",
            "rate_limited"
        )

    username = (
        ldb.normalize_username(msg.get("username")) or ""
    )

    token = str(msg.get("token", "")).strip()

    if not username or not token:
        return await fail(
            ws,
            "login_result",
            "bad_credentials"
        )

    row = ldb.get_by_username(username)

    if not row:
        record("fail", ip)
        return await fail(
            ws,
            "login_result",
            "bad_credentials"
        )

    code = row["code"]

    if locked(code):
        return await fail(
            ws,
            "login_result",
            "locked"
        )

    ok, reason = ldb.usable(row)

    if not ok:
        return await fail(
            ws,
            "login_result",
            reason
        )

    if not ldb.check_token(row, token):
        record("fail", ip)
        auth_fails[code].append(time.time())

        return await fail(
            ws,
            "login_result",
            "session_expired"
        )

    await start_session(ws, row)


async def on_login_verify(ws, ip, msg):
    if over("fail", ip, 15, 600):
        return await fail(
            ws,
            "login_result",
            "rate_limited"
        )

    row = ldb.get_by_username(
        ldb.normalize_username(msg.get("username")) or ""
    )

    code = row and row["code"]

    if code and locked(code):
        return await fail(
            ws,
            "login_result",
            "locked"
        )

    secret = str(msg.get("secret", "")).strip()

    if not ldb.check_password(row, msg.get("password", "")):
        record("fail", ip)

        if code:
            auth_fails[code].append(time.time())

        return await fail(
            ws,
            "login_result",
            "bad_credentials"
        )

    ok, reason = ldb.usable(row)

    if not ok:
        return await fail(
            ws,
            "login_result",
            reason
        )

    why = check_otp(
        otp_state.get(code),
        code,
        str(msg.get("otp", "")).strip()
    )

    if why:
        if why == "wrong_otp":
            record("fail", ip)

        return await fail(
            ws,
            "login_result",
            why
        )

    if not ldb.check_pin(row, secret):
        record("fail", ip)
        auth_fails[code].append(time.time())

        return await fail(
            ws,
            "login_result",
            "bad_secret"
        )

    token = secrets.token_urlsafe(32)

    res = ldb.bind_phone(
        code,
        token,
        secret
    )

    if res != "ok":
        return await fail(
            ws,
            "login_result",
            res
        )

    otp_state[code]["hash"] = None

    await start_session(
        ws,
        ldb.get_license(code),
        new_token=token
    )


# ----------------------------------------------------------------
# الاتصال بالكمبيوتر
# ----------------------------------------------------------------

async def on_connect_pc(ws, ip, msg):
    info = session_of(ws, "authed")

    if not info:
        return await fail(
            ws,
            "auth_result",
            "bad_credentials"
        )

    code = info[0]
    r = rooms.get(code)

    if not r or not r.get("agent"):
        return await fail(
            ws,
            "auth_result",
            "agent_offline"
        )

    r["pending"] = None

    await kick_control(
        code,
        except_ws=ws
    )

    r["control"] = ws
    ws_info[ws] = (code, "control")

    await safe_send(
        r["agent"],
        {
            "type": "controller",
            "connected": True
        }
    )

    await reply(
        ws,
        "auth_result",
        ok=True
    )


async def on_pc_status(ws, ip, msg):
    info = session_of(ws, "authed")

    if info:
        r = rooms.get(info[0]) or {}
        row = ldb.get_license(info[0]) or {}

        await reply(
            ws,
            "pc_status",
            online=bool(r.get("agent")),
            name=row.get("agent_name") or ""
        )


async def kick_control(code, except_ws=None):
    r = rooms.get(code)
    old = r.get("control") if r else None

    if old and old is not except_ws:
        r["control"] = None

        await safe_send(
            old,
            {"type": "kicked"}
        )

        await safe_close(old)


# ----------------------------------------------------------------
# ربط الكمبيوتر بالجوال
# ----------------------------------------------------------------

def clean_pair_codes():
    now = time.time()

    for code, data in list(pending_pairs.items()):
        if now > data["exp"] or data["ws"].closed:
            pending_pairs.pop(code, None)


async def on_pair_request(ws, ip, msg):
    if ws_info.get(ws):
        return await safe_send(
            ws,
            {
                "type": "pair_error",
                "reason": "already_registered"
            }
        )

    if over("pair_request", ip, 10, 600):
        return await safe_send(
            ws,
            {
                "type": "pair_error",
                "reason": "rate_limited"
            }
        )

    hwid = str(msg.get("hwid", "")).strip()[:200]
    name = str(msg.get("name", "Computer")).strip()[:60]

    if not hwid:
        return await safe_send(
            ws,
            {
                "type": "pair_error",
                "reason": "bad_device"
            }
        )

    record("pair_request", ip)
    clean_pair_codes()

    for old_code, data in list(pending_pairs.items()):
        if data["ws"] is ws:
            pending_pairs.pop(old_code, None)

    code = None

    for _ in range(20):
        candidate = f"{secrets.randbelow(100_000_000):08d}"

        if candidate not in pending_pairs:
            code = candidate
            break

    if not code:
        return await safe_send(
            ws,
            {
                "type": "pair_error",
                "reason": "server_busy"
            }
        )

    pending_pairs[code] = {
        "ws": ws,
        "hwid": hwid,
        "name": name,
        "ip": ip,
        "exp": time.time() + PAIR_TTL
    }

    print(
        f"[PAIR] New pairing request: {name} ({code})",
        flush=True
    )

    await safe_send(
        ws,
        {
            "type": "pair_code",
            "ok": True,
            "code": code,
            "ttl": PAIR_TTL
        }
    )


async def on_pair_confirm(ws, ip, msg):
    info = session_of(ws, "authed")

    if not info:
        return await fail(
            ws,
            "pair_result",
            "bad_credentials"
        )

    code = info[0]
    row = ldb.get_license(code)

    if not row:
        return await fail(
            ws,
            "pair_result",
            "license_not_found"
        )

    ok, reason = ldb.usable(row)

    if not ok:
        return await fail(
            ws,
            "pair_result",
            reason
        )

    if not row.get("phone_token_hash"):
        return await fail(
            ws,
            "pair_result",
            "phone_not_bound"
        )

    pair_code = re.sub(
        r"\D",
        "",
        str(msg.get("code", ""))
    )

    if not re.fullmatch(r"\d{8}", pair_code):
        return await fail(
            ws,
            "pair_result",
            "bad_pair_code"
        )

    clean_pair_codes()

    pairing = pending_pairs.pop(
        pair_code,
        None
    )

    if not pairing:
        return await fail(
            ws,
            "pair_result",
            "bad_pair_code"
        )

    agent_ws = pairing["ws"]

    if agent_ws.closed:
        return await fail(
            ws,
            "pair_result",
            "agent_offline"
        )

    machine_hash = _h(
        "hw:" + pairing["hwid"]
    )

    bound, why = ldb.bind_agent(
        code,
        machine_hash
    )

    if not bound:
        return await fail(
            ws,
            "pair_result",
            why or "device_mismatch"
        )

    agent_token = secrets.token_urlsafe(32)

    ldb.set_agent_token(
        code,
        agent_token
    )

    ldb.set_agent_info(
        code,
        pairing["ip"],
        pairing["name"]
    )

    await safe_send(
        agent_ws,
        {
            "type": "pair_done",
            "username": row["username"],
            "agent_token": agent_token
        }
    )

    print(
        f"[PAIR] Successfully paired: {row['username']} / {pairing['name']}",
        flush=True
    )

    await reply(
        ws,
        "pair_result",
        ok=True,
        name=pairing["name"]
    )


# ----------------------------------------------------------------
# تسجيل الـ Agent
# ----------------------------------------------------------------

async def on_register_agent(ws, ip, msg):
    hwid = str(msg.get("hwid", ""))[:200]
    name = str(msg.get("name", ""))[:60]

    def deny(reason):
        return safe_send(
            ws,
            {
                "type": "registered_agent",
                "ok": False,
                "reason": reason
            }
        )

    if over("fail", ip, 15, 600):
        return await deny("rate_limited")

    row = ldb.get_by_username(
        ldb.normalize_username(msg.get("username")) or ""
    )

    code = row and row["code"]

    if not row or not hwid:
        record("fail", ip)
        return await deny("bad_credentials")

    if locked(code):
        return await deny("locked")

    by_token = ldb.check_agent_token(
        row,
        msg.get("agent_token", "")
    )

    if not (
        by_token
        or ldb.check_password(
            row,
            msg.get("password", "")
        )
    ):
        record("fail", ip)
        auth_fails[code].append(time.time())

        return await deny("bad_credentials")

    ok, reason = ldb.usable(row)

    if not ok:
        return await deny(reason)

    bound, why = ldb.bind_agent(
        code,
        _h("hw:" + hwid)
    )

    if not bound:
        record("fail", ip)
        return await deny(why)

    ldb.set_agent_info(
        code,
        ip,
        name
    )

    new_token = None

    if not by_token:
        new_token = secrets.token_urlsafe(32)
        ldb.set_agent_token(code, new_token)

    r = rooms.setdefault(
        code,
        {
            "agent": None,
            "control": None,
            "pending": None
        }
    )

    old = r.get("agent")

    if old and old is not ws:
        await safe_close(old)

    r["agent"] = ws
    ws_info[ws] = (code, "agent")

    await safe_send(
        ws,
        {
            "type": "registered_agent",
            "ok": True,
            "agent_token": new_token
        }
    )

    for w in (
        r.get("control"),
        r.get("pending")
    ):
        if w:
            await safe_send(
                w,
                {
                    "type": "agent_online",
                    "name": name
                }
            )


# ----------------------------------------------------------------
# تنظيف الاتصالات
# ----------------------------------------------------------------

async def cleanup(ws):
    for code, data in list(pending_pairs.items()):
        if data["ws"] is ws:
            pending_pairs.pop(code, None)

    info = ws_info.pop(ws, None)

    if not info:
        return

    code, role = info
    r = rooms.get(code)

    if not r:
        return

    if role == "agent" and r.get("agent") is ws:
        r["agent"] = None

        control = r.get("control")
        pending = r.get("pending")

        for w in (control, pending):
            if w:
                await safe_send(
                    w,
                    {
                        "type": "agent_offline"
                    }
                )

    elif role == "control" and r.get("control") is ws:
        r["control"] = None

        if r.get("agent"):
            await safe_send(
                r["agent"],
                {
                    "type": "controller",
                    "connected": False
                }
            )

    elif role == "authed" and r.get("pending") is ws:
        r["pending"] = None


# ----------------------------------------------------------------
# تمرير الرسائل بين الجوال والكمبيوتر
# ----------------------------------------------------------------

async def forward(ws, msg):
    info = ws_info.get(ws)

    if not info:
        return

    code, role = info
    r = rooms.get(code)

    if not r:
        return

    # أوامر الجوال تذهب إلى الكمبيوتر
    if role == "control" and r.get("agent"):
        await safe_send(r["agent"], msg)

    # رسائل الكمبيوتر ترجع إلى الجوال
    elif (
        role == "agent"
        and r.get("control")
        and msg.get("type") in (
            "frame",
            "audio_frame",
            "monitors",
            "monitor_selected",
        )
    ):
        await safe_send(r["control"], msg)


# ----------------------------------------------------------------
# معالجات WebSocket
# ----------------------------------------------------------------

HANDLERS = {
    "pair_request": on_pair_request,
    "pair_confirm": on_pair_confirm,

    "signup_start": on_signup_start,
    "signup_verify": on_signup_verify,
    "set_credentials": on_set_credentials,

    "login": on_login,
    "resume_login": on_resume_login,
    "login_verify": on_login_verify,

    "connect_pc": on_connect_pc,
    "pc_status": on_pc_status,

    "register_agent": on_register_agent,
}


async def ws_handler(request):
    ws = web.WebSocketResponse(
        heartbeat=20,
        max_msg_size=4 * 1024 * 1024
    )

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

            handler = HANDLERS.get(
                msg.get("type")
            )

            if handler:
                await handler(ws, ip, msg)
            else:
                await forward(ws, msg)

    finally:
        await cleanup(ws)

    return ws


# ----------------------------------------------------------------
# فرض الترخيص
# ----------------------------------------------------------------

async def enforcer():
    while True:
        await asyncio.sleep(ENFORCE_INTERVAL)

        for code, r in list(rooms.items()):
            row = ldb.get_license(code)

            ok = (
                bool(row)
                and ldb.usable(row)[0]
                and bool(row["phone_token_hash"])
            )

            if ok:
                continue

            targets = [
                w for w in (
                    r.get("agent"),
                    r.get("control"),
                    r.get("pending")
                )
                if w
            ]

            for w in targets:
                await safe_send(
                    w,
                    {"type": "license_ended"}
                )

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


# ----------------------------------------------------------------
# الملفات الثابتة
# ----------------------------------------------------------------

NO_CACHE = {
    "Cache-Control": "no-cache"
}


async def index(request):
    return web.FileResponse(
        os.path.join(BASE_DIR, "control.html"),
        headers=NO_CACHE
    )


async def asset(request):
    path = os.path.join(
        BASE_DIR,
        os.path.basename(request.path)
    )

    if not os.path.isfile(path):
        raise web.HTTPNotFound()

    return web.FileResponse(
        path,
        headers=NO_CACHE
    )


async def health(request):
    return web.json_response({
        "ok": True
    })


# ----------------------------------------------------------------
# تحميل برنامج Agent
# ----------------------------------------------------------------

async def download_agent(request):
    path = os.path.join(
        BASE_DIR,
        "agent.exe"
    )

    print(
        "[DOWNLOAD] BASE_DIR:",
        BASE_DIR,
        flush=True
    )

    print(
        "[DOWNLOAD] FILE:",
        path,
        flush=True
    )

    print(
        "[DOWNLOAD] EXISTS:",
        os.path.isfile(path),
        flush=True
    )

    if not os.path.isfile(path):
        raise web.HTTPNotFound(
            text="agent.exe not found on server"
        )

    return web.FileResponse(
        path,
        headers={
            "Content-Disposition": 'attachment; filename="agent.exe"',
            "Cache-Control": "no-cache"
        }
    )


# ----------------------------------------------------------------
# إدارة التراخيص
# ----------------------------------------------------------------

ADMIN_TOKEN = os.environ.get(
    "ADMIN_TOKEN",
    ""
).strip()


async def admin_run(request):
    if len(ADMIN_TOKEN) < 16:
        return web.json_response(
            {
                "ok": False,
                "error": "disabled"
            },
            status=404
        )

    ip = client_ip(request)

    if over("admin_fail", ip, 5, 900):
        return web.json_response(
            {
                "ok": False,
                "error": "rate_limited"
            },
            status=429
        )

    auth = request.headers.get(
        "Authorization",
        ""
    )

    if not hmac.compare_digest(
        auth.encode(),
        ("Bearer " + ADMIN_TOKEN).encode()
    ):
        record("admin_fail", ip)

        return web.json_response(
            {
                "ok": False,
                "error": "unauthorized"
            },
            status=401
        )

    try:
        args = (await request.json()).get("args")

        assert (
            isinstance(args, list)
            and all(isinstance(a, str) for a in args)
            and len(args) < 20
        )

    except Exception:
        return web.json_response(
            {
                "ok": False,
                "error": "bad_request"
            },
            status=400
        )

    here = os.path.dirname(
        os.path.abspath(__file__)
    )

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        os.path.join(here, "admin.py"),
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={
            **os.environ,
            "RC_ADMIN_URL": ""
        }
    )

    out, _ = await asyncio.wait_for(
        proc.communicate(),
        20
    )

    return web.json_response({
        "ok": proc.returncode == 0,
        "output": out.decode(
            "utf-8",
            "replace"
        )
    })


# ----------------------------------------------------------------
# لوحة البائع
# ----------------------------------------------------------------

SELLER_USER = os.environ.get(
    "SELLER_USERNAME",
    ""
).strip()

SELLER_PASS = os.environ.get(
    "SELLER_PASSWORD",
    ""
)

SELLER_COOKIE = "rc_seller"
SELLER_TTL = 12 * 3600

seller_sessions = {}


LOGIN_HTML = """<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>دخول البائع</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#071b16;color:#edf8f2;font-family:Tahoma,Arial,sans-serif}
form{background:#0d2a22;border:1px solid #235344;border-radius:14px;padding:28px;width:min(92vw,360px)}
h1{color:#8ee5ad;font-size:22px;margin:0 0 18px}input{display:block;width:100%;margin:10px 0;padding:12px;border-radius:8px;border:1px solid #235344;background:#061a14;color:#fff}
button{width:100%;margin-top:8px;padding:12px;border:0;border-radius:8px;background:#8ee5ad;color:#092318;font-weight:700;cursor:pointer}#e{color:#ff8585;min-height:22px;font-size:14px}</style></head>
<body><form id="f"><h1>دخول البائع</h1>
<input id="u" placeholder="اسم المستخدم" autocomplete="username" autocapitalize="none">
<input id="p" type="password" placeholder="كلمة المرور" autocomplete="current-password">
<div id="e"></div><button>دخول</button></form>
<script>document.getElementById('f').addEventListener('submit',async ev=>{ev.preventDefault();
const e=document.getElementById('e');e.textContent='';
try{const r=await fetch('/seller/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
body:JSON.stringify({username:u.value,password:p.value})});
if(r.ok){location.reload();return}
e.textContent=r.status===429?'محاولات كثيرة، جرّب بعد 15 دقيقة':'بيانات الدخول غير صحيحة'}
catch(x){e.textContent='تعذر الاتصال بالسيرفر'}});</script></body></html>"""


def seller_enabled():
    return (
        bool(SELLER_USER)
        and len(SELLER_PASS) >= 8
    )


def seller_authed(request):
    sid = request.cookies.get(
        SELLER_COOKIE,
        ""
    )

    exp = seller_sessions.get(sid)

    if exp and exp > time.time():
        return True

    seller_sessions.pop(sid, None)
    return False


def same_origin(request):
    origin = request.headers.get("Origin")

    return (
        not origin
        or urlparse(origin).netloc == request.host
    )


def seller_json(data, status=200):
    return web.json_response(
        data,
        status=status,
        headers=NO_CACHE
    )


async def seller_page(request):
    if not seller_enabled():
        raise web.HTTPNotFound()

    if seller_authed(request):
        return web.FileResponse(
            os.path.join(BASE_DIR, "seller.html"),
            headers=NO_CACHE
        )

    return web.Response(
        text=LOGIN_HTML,
        content_type="text/html",
        headers=NO_CACHE
    )


async def seller_login(request):
    if not seller_enabled():
        raise web.HTTPNotFound()

    ip = client_ip(request)

    if not same_origin(request):
        return seller_json(
            {
                "ok": False,
                "error": "forbidden"
            },
            403
        )

    if over("seller_fail", ip, 5, 900):
        return seller_json(
            {
                "ok": False,
                "error": "rate_limited"
            },
            429
        )

    try:
        d = await request.json()

        u = str(d.get("username", ""))
        p = str(d.get("password", ""))

    except Exception:
        return seller_json(
            {
                "ok": False,
                "error": "bad_request"
            },
            400
        )

    ok_u = hmac.compare_digest(
        u.encode(),
        SELLER_USER.encode()
    )

    ok_p = hmac.compare_digest(
        p.encode(),
        SELLER_PASS.encode()
    )

    if not (ok_u and ok_p):
        record("seller_fail", ip)

        return seller_json(
            {
                "ok": False,
                "error": "unauthorized"
            },
            401
        )

    sid = secrets.token_urlsafe(32)
    now = time.time()

    for k in [
        k for k, v in seller_sessions.items()
        if v < now
    ]:
        seller_sessions.pop(k, None)

    seller_sessions[sid] = now + SELLER_TTL

    resp = seller_json({
        "ok": True
    })

    secure = (
        request.headers.get(
            "X-Forwarded-Proto",
            request.scheme
        ) == "https"
    )

    resp.set_cookie(
        SELLER_COOKIE,
        sid,
        max_age=SELLER_TTL,
        httponly=True,
        samesite="Strict",
        secure=secure,
        path="/"
    )

    return resp


def seller_guard(request):
    if not seller_enabled():
        raise web.HTTPNotFound()

    if not seller_authed(request):
        return seller_json(
            {
                "ok": False,
                "error": "unauthorized"
            },
            401
        )

    if (
        request.method != "GET"
        and not same_origin(request)
    ):
        return seller_json(
            {
                "ok": False,
                "error": "forbidden"
            },
            403
        )

    return None


async def seller_list(request):
    bad = seller_guard(request)

    if bad:
        return bad

    rows = ldb.list_licenses()

    rows.sort(
        key=lambda r: (
            r["status"] != "pending",
            -r["created_at"]
        )
    )

    out = [
        {
            "code": r["code"],
            "username": r.get("username"),
            "status": r["status"],
            "masked_contact": (
                ldb.mask_contact(
                    r["channel"],
                    r["contact"]
                )
                if r["contact"]
                else ""
            ),
            "expires_at": r["expires_at"],
            "created_at": r["created_at"],
            "agent_name": r.get("agent_name"),
            "agent_ip": r.get("agent_ip"),
            "has_pc": bool(r["agent_hash"]),
            "has_phone": bool(r["phone_token_hash"]),
            "phone_binds": r["phone_binds"],
            "online": bool(
                (rooms.get(r["code"]) or {}).get("agent")
            )
        }
        for r in rows
    ]

    return seller_json({
        "ok": True,
        "licenses": out
    })


SELLER_ACTIONS = (
    "activate",
    "extend",
    "revoke",
    "restore",
    "reset_agent",
    "reset_phone",
    "delete"
)


async def seller_action(request):
    bad = seller_guard(request)

    if bad:
        return bad

    code = ldb.normalize_code(
        request.match_info["code"]
    )

    action = request.match_info["action"]
    row = code and ldb.get_license(code)

    if not row or action not in SELLER_ACTIONS:
        return seller_json(
            {
                "ok": False,
                "error": "not_found"
            },
            404
        )

    now = int(time.time())

    if action in ("activate", "extend"):
        try:
            days = int(
                (await request.json()).get("days")
            )

            assert 1 <= days <= 3650

        except Exception:
            return seller_json(
                {
                    "ok": False,
                    "error": "أدخل عدد أيام من 1 إلى 3650"
                },
                400
            )

        with ldb.db() as c:
            if action == "activate":
                c.execute(
                    "UPDATE licenses SET status='active', expires_at=? WHERE code=?",
                    (
                        now + days * 86400,
                        code
                    )
                )

            else:
                base = max(
                    now,
                    row["expires_at"] or 0
                )

                c.execute(
                    "UPDATE licenses SET expires_at=? WHERE code=?",
                    (
                        base + days * 86400,
                        code
                    )
                )

    elif action == "revoke":
        ldb.set_status(code, "revoked")

    elif action == "restore":
        ldb.set_status(code, "active")

    elif action == "reset_agent":
        ldb.reset(code, "agent")

    elif action == "reset_phone":
        ldb.reset(code, "phone")

    elif action == "delete":
        with ldb.db() as c:
            c.execute(
                "DELETE FROM licenses WHERE code=?",
                (code,)
            )

    return seller_json({
        "ok": True
    })


async def seller_logout(request):
    if not same_origin(request):
        return seller_json(
            {
                "ok": False,
                "error": "forbidden"
            },
            403
        )

    seller_sessions.pop(
        request.cookies.get(SELLER_COOKIE, ""),
        None
    )

    resp = seller_json({
        "ok": True
    })

    resp.del_cookie(
        SELLER_COOKIE,
        path="/"
    )

    return resp


# ----------------------------------------------------------------
# تشغيل التطبيق
# ----------------------------------------------------------------

def make_app():
    app = web.Application()

    app.router.add_post(
        "/admin/run",
        admin_run
    )

    app.router.add_get(
        "/seller",
        seller_page
    )

    app.router.add_post(
        "/seller/login",
        seller_login
    )

    app.router.add_post(
        "/seller/logout",
        seller_logout
    )

    app.router.add_get(
        "/seller/api/licenses",
        seller_list
    )

    app.router.add_post(
        "/seller/api/licenses/{code}/{action}",
        seller_action
    )

    app.router.add_get("/", index)
    app.router.add_get("/control.html", index)

    for name in (
        "manifest.json",
        "sw.js",
        "icon-192.png",
        "icon-512.png",
        "icon-512-maskable.png"
    ):
        app.router.add_get(
            "/" + name,
            asset
        )

    app.router.add_get(
        "/health",
        health
    )

    app.router.add_get(
        "/download/agent.exe",
        download_agent
    )

    app.router.add_get(
        "/ws",
        ws_handler
    )

    app.cleanup_ctx.append(background)

    return app


def main():
    ldb.init_db()

    print("=" * 56)
    print("  السيرفر الوسيط + التراخيص شغّال ✅")
    print("=" * 56)

    print(f"  المنفذ: {PORT}")
    print(f"  إرسال الرموز: {otpmod.describe()}")

    print(
        f"  لوحة البائع: "
        f"{'/seller (مفعّلة)' if seller_enabled() else 'مقفولة (ضع SELLER_USERNAME و SELLER_PASSWORD 8+ أحرف)'}"
    )

    print(
        f"  وضع التسجيل: {SIGNUP_MODE}  "
        f"(approval = الحساب ينتظر تفعيلك بعد الدفع | open = فوري)"
    )

    if otpmod.is_dev_mode():
        print(
            "  ⚠️ وضع تجربة: الرمز يطبع هنا بدل ما يوصل للمشتري (راجع otp.py)"
        )

    print("  إدارة التراخيص: python admin.py --help")
    print("=" * 56, flush=True)

    web.run_app(
        make_app(),
        host=os.environ.get("HOST", "0.0.0.0"),
        port=PORT,
        print=None
    )


if __name__ == "__main__":
    main()
