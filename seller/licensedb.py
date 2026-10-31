from pathlib import Path

code = r'''# -*- coding: utf-8 -*-
"""قاعدة بيانات التراخيص باستخدام PostgreSQL (Prisma Postgres).
يستخدمها السيرفر الوسيط وأداة الإدارة فقط.
"""

import contextlib
import hashlib
import hmac
import os
import re
import secrets
import sys
import time

import psycopg
from psycopg.rows import dict_row


def _base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# DATABASE_URL يضاف في Render. RC_DB لم يعد مستخدماً مع PostgreSQL.
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
MAX_PHONE_BINDS = 5
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@contextlib.contextmanager
def db():
    if not DATABASE_URL:
        raise RuntimeError("متغير DATABASE_URL غير مضبوط في إعدادات السيرفر")
    conn = psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=15,
        prepare_threshold=None,  # توافق أفضل مع connection pooling
    )
    try:
        with conn.transaction():
            yield conn
    finally:
        conn.close()


def init_db():
    with db() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS licenses(
                code TEXT PRIMARY KEY,
                channel TEXT NOT NULL,
                contact TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                created_at BIGINT NOT NULL,
                expires_at BIGINT,
                agent_hash TEXT,
                phone_token_hash TEXT,
                pin_salt TEXT,
                pin_hash TEXT,
                phone_binds INTEGER NOT NULL DEFAULT 0,
                activated_at BIGINT,
                username TEXT,
                pw_salt TEXT,
                pw_hash TEXT,
                agent_ip TEXT,
                agent_name TEXT,
                agent_token_hash TEXT
            )"""
        )
        # يدعم أيضاً قاعدة موجودة مسبقاً بإصدار أقدم من الجدول.
        for col in ("username", "pw_salt", "pw_hash", "agent_ip", "agent_name", "agent_token_hash"):
            c.execute(f"ALTER TABLE licenses ADD COLUMN IF NOT EXISTS {col} TEXT")
        c.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_license_username ON licenses(username)"
        )


# ---------------------------------------------------------------- تنسيق المدخلات
def normalize_code(raw):
    s = re.sub(
        r"\D", "",
        str(raw or "").translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789"))
    )
    return s if len(s) == 6 else None


def normalize_phone(raw):
    s = str(raw or "").strip()
    plus = s.startswith("+")
    d = re.sub(r"\D", "", s)
    if not d:
        return None
    if d.startswith("00"):
        d, plus = d[2:], True
    elif d.startswith("05") and len(d) == 10:
        d = "966" + d[1:]
    elif d.startswith("5") and len(d) == 9:
        d = "966" + d
    elif not plus and not d.startswith("966"):
        return None
    if not 10 <= len(d) <= 15:
        return None
    return "+" + d


def parse_contact(raw):
    """يحدد هل المدخل إيميل أو جوال ويرجّعه منسّق: (channel, contact) أو None."""
    s = str(raw or "").strip()
    if "@" in s:
        s = s.lower()
        return ("email", s) if EMAIL_RE.match(s) and len(s) <= 120 else None
    p = normalize_phone(s)
    return ("sms", p) if p else None


def claim_contact(code, channel, contact):
    """أول تفعيل: يربط جوال/إيميل المشتري بالترخيص (مرة وحدة فقط)."""
    with db() as c:
        cur = c.execute(
            "UPDATE licenses SET channel=%s, contact=%s WHERE code=%s AND contact=''",
            (channel, contact, code),
        )
        return cur.rowcount > 0


def mask_contact(channel, contact):
    if not contact:
        return "— (المشتري يسجّل جواله/إيميله عند التفعيل)"
    if channel == "email":
        name, _, domain = contact.partition("@")
        return f"{name[:1]}***@{domain}"
    return f"{contact[:4]}•••••{contact[-3:]}"


# ---------------------------------------------------------------- التراخيص
def create_license(channel, contact, note="", days=None):
    if not channel:
        channel, contact = "", ""
    elif channel == "email":
        contact = str(contact).strip().lower()
        if not EMAIL_RE.match(contact):
            raise ValueError("البريد الإلكتروني غير صالح")
    elif channel == "sms":
        contact = normalize_phone(contact)
        if not contact:
            raise ValueError("رقم الجوال غير صالح (مثال: 0555123456)")
    else:
        raise ValueError("القناة لازم تكون email أو sms")

    now = int(time.time())
    expires = now + int(days) * 86400 if days else None
    with db() as c:
        for _ in range(20):
            code = "".join(secrets.choice("0123456789") for _ in range(6))
            try:
                c.execute(
                    "INSERT INTO licenses(code,channel,contact,note,created_at,expires_at) "
                    "VALUES(%s,%s,%s,%s,%s,%s)",
                    (code, channel, contact, note, now, expires),
                )
                return code
            except psycopg.errors.UniqueViolation:
                # أزل حالة الخطأ داخل المعاملة قبل إعادة المحاولة.
                # نستخدم SAVEPOINT حتى لا تُلغى المعاملة كاملة.
                raise RuntimeError("حدث تعارض نادر أثناء توليد كود الترخيص؛ أعد المحاولة")
    raise RuntimeError("تعذر توليد كود فريد")


def get_license(code):
    with db() as c:
        row = c.execute("SELECT * FROM licenses WHERE code=%s", (code,)).fetchone()
    return dict(row) if row else None


def list_licenses():
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM licenses ORDER BY created_at DESC"
        ).fetchall()]


def usable(row):
    if row["status"] == "pending":
        return False, "pending"
    if row["status"] != "active":
        return False, "revoked"
    if row["expires_at"] and row["expires_at"] < time.time():
        return False, "expired"
    return True, None


def set_status(code, status):
    with db() as c:
        cur = c.execute(
            "UPDATE licenses SET status=%s WHERE code=%s", (status, code)
        )
        return cur.rowcount > 0


def reset(code, what="all"):
    """يفك ربط الجهاز/الجوال."""
    sets = []
    if what in ("agent", "all"):
        sets += [
            "agent_hash=NULL", "agent_ip=NULL",
            "agent_name=NULL", "agent_token_hash=NULL"
        ]
    if what in ("phone", "all"):
        sets += [
            "phone_token_hash=NULL", "pin_salt=NULL",
            "pin_hash=NULL", "phone_binds=0"
        ]
    if not sets:
        return False
    with db() as c:
        cur = c.execute(
            f"UPDATE licenses SET {', '.join(sets)} WHERE code=%s", (code,)
        )
        return cur.rowcount > 0


# ---------------------------------------------------------------- ربط الأجهزة
def bind_agent(code, machine_hash):
    with db() as c:
        c.execute(
            "UPDATE licenses SET agent_hash=%s WHERE code=%s AND agent_hash IS NULL",
            (machine_hash, code),
        )
        row = c.execute(
            "SELECT agent_hash FROM licenses WHERE code=%s", (code,)
        ).fetchone()
    if not row:
        return False, "invalid"
    if hmac.compare_digest(row["agent_hash"] or "", machine_hash):
        return True, None
    return False, "device_mismatch"


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def hash_pin(pin, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", pin.encode(), salt.encode(), 100_000
    ).hex()


def bind_phone(code, token, pin):
    salt = secrets.token_hex(8)
    with db() as c:
        row = c.execute(
            "SELECT phone_binds FROM licenses WHERE code=%s", (code,)
        ).fetchone()
        if not row:
            return "invalid"
        if row["phone_binds"] >= MAX_PHONE_BINDS:
            return "rebind_limit"
        c.execute(
            "UPDATE licenses SET phone_token_hash=%s, pin_salt=%s, pin_hash=%s, "
            "phone_binds=phone_binds+1, activated_at=COALESCE(activated_at, %s) "
            "WHERE code=%s",
            (hash_token(token), salt, hash_pin(pin, salt), int(time.time()), code),
        )
    return "ok"


def check_token(row, token):
    h = row.get("phone_token_hash")
    return bool(h) and hmac.compare_digest(hash_token(token), h)


def check_pin(row, pin):
    if not row.get("pin_hash") or not row.get("pin_salt"):
        return False
    return hmac.compare_digest(
        hash_pin(pin, row["pin_salt"]), row["pin_hash"]
    )


# ---------------------------------------------------------------- الحسابات (تسجيل ذاتي)
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,19}$")


def normalize_username(raw):
    u = str(raw or "").strip().lower()
    return u if USERNAME_RE.match(u) else None


def get_by_username(username):
    with db() as c:
        row = c.execute(
            "SELECT * FROM licenses WHERE username=%s", (username,)
        ).fetchone()
    return dict(row) if row else None


def get_by_contact(contact):
    with db() as c:
        row = c.execute(
            "SELECT * FROM licenses WHERE contact=%s "
            "ORDER BY (username IS NULL) ASC LIMIT 1",
            (contact,),
        ).fetchone()
    return dict(row) if row else None


def find(ident):
    """يلقى الحساب باسم المستخدم أو بالرقم الداخلي (6 أرقام)."""
    ident = str(ident or "").strip()
    code = normalize_code(ident)
    row = get_license(code) if code else None
    return row or get_by_username(ident.lower())


def set_credentials(code, username, password):
    salt = secrets.token_hex(8)
    try:
        with db() as c:
            cur = c.execute(
                "UPDATE licenses SET username=%s, pw_salt=%s, pw_hash=%s "
                "WHERE code=%s AND username IS NULL",
                (username, salt, hash_pin(password, salt), code),
            )
            return "ok" if cur.rowcount else "exists"
    except psycopg.errors.UniqueViolation:
        return "taken"


def check_password(row, password):
    """يقارن دائمًا (حتى لو المستخدم غير موجود) عشان ما يتسرّب وجوده بالزمن."""
    salt = (row or {}).get("pw_salt") or "00000000"
    expected = (row or {}).get("pw_hash") or ("0" * 64)
    ok = hmac.compare_digest(hash_pin(str(password), salt), expected)
    return bool(row) and bool(row.get("pw_hash")) and ok


def set_agent_info(code, ip, name):
    with db() as c:
        c.execute(
            "UPDATE licenses SET agent_ip=%s, agent_name=%s WHERE code=%s",
            (ip, name, code),
        )


def set_agent_token(code, token):
    with db() as c:
        c.execute(
            "UPDATE licenses SET agent_token_hash=%s WHERE code=%s",
            (hash_token(token), code),
        )


def check_agent_token(row, token):
    h = row.get("agent_token_hash")
    return bool(h) and bool(token) and hmac.compare_digest(
        hash_token(str(token)), h
    )


def set_contact(code, channel, contact):
    with db() as c:
        c.execute(
            "UPDATE licenses SET channel=%s, contact=%s WHERE code=%s",
            (channel, contact, code),
        )
'''

