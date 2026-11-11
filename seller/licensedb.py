# -*- coding: utf-8 -*-
"""قاعدة بيانات التراخيص (SQLite) — يستخدمها السيرفر الوسيط وأداة الإدارة فقط.
لا تعطِ هذا الملف للمشتري."""

import atexit
import contextlib
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import sys
import threading
import time


def _base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


DB_PATH = os.environ.get("RC_DB") or os.path.join(_base_dir(), "licenses.db")
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # بدون 0/O/1/I عشان ما يلخبط
MAX_PHONE_BINDS = 5  # كم مرة يقدر يربط جوال (الأولى + تغييرات) قبل ما تحتاج تسوي reset
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@contextlib.contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    changed = False
    try:
        yield conn
        conn.commit()
        changed = conn.total_changes > 0
    finally:
        conn.close()
    if changed:
        _cloud_dirty()


# ---------------------------------------------------------------- حفظ سحابي مجاني (اختياري)
# الاستضافة المجانية تمسح الملفات عند كل إعادة تشغيل. لو ضبطت DATABASE_URL (قاعدة Postgres
# مجانية مثل Neon أو Supabase) نحفظ نسخة كاملة من القاعدة هناك بعد كل تعديل، ونستعيدها عند الإقلاع.
CLOUD_URL = os.environ.get("DATABASE_URL", "").strip()
_cloud_lock = threading.Lock()
_cloud_timer = None
_cloud_enabled = False
_cloud_ver = 0


def _pg():
    import psycopg2
    conn = psycopg2.connect(CLOUD_URL, connect_timeout=15)
    with conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS rc_backup(id INTEGER PRIMARY KEY, data BYTEA NOT NULL, updated BIGINT NOT NULL)")
    conn.commit()
    return conn


def _cloud_load():
    """يرجع (بايتات, رقم_نسخة) لآخر نسخة محفوظة أو (None, 0)."""
    conn = _pg()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT data, updated FROM rc_backup WHERE id=1")
            row = cur.fetchone()
        return (bytes(row[0]), int(row[1])) if row else (None, 0)
    finally:
        conn.close()


def _cloud_save(data, expected_ver):
    """يحفظ فقط لو النسخة السحابية ما تغيّرت من آخر مرة شفناها (حماية من نسختين شغّالتين معًا).
    يرجع (True, رقم_جديد) أو (False, (بايتات_السحابة, رقمها)) عند التعارض."""
    conn = _pg()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT data, updated FROM rc_backup WHERE id=1 FOR UPDATE")
            row = cur.fetchone()
            if row and int(row[1]) != expected_ver:
                return False, (bytes(row[0]), int(row[1]))
            new_ver = time.time_ns() // 1000
            cur.execute(
                "INSERT INTO rc_backup(id,data,updated) VALUES(1,%s,%s) "
                "ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, updated=EXCLUDED.updated",
                (data, new_ver))
        conn.commit()
        return True, new_ver
    finally:
        conn.close()


def _snapshot():
    src = sqlite3.connect(DB_PATH, timeout=10)
    try:
        return src.serialize()
    finally:
        src.close()


def _write_local(data):
    tmp = DB_PATH + ".restore"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, DB_PATH)


def _cloud_push():
    global _cloud_timer, _cloud_ver
    with _cloud_lock:
        _cloud_timer = None
        try:
            ok, res = _cloud_save(_snapshot(), _cloud_ver)
            if ok:
                _cloud_ver = res
            else:
                # نسخة ثانية من السيرفر كتبت قبلنا: نعتمد نسختها بدل ما نكتب فوقها بنسخة قديمة
                data, ver = res
                _write_local(data)
                _cloud_ver = ver
                print("[حفظ سحابي] تعارض: اعتمدت النسخة الأحدث من السحابة", flush=True)
        except Exception as e:  # لا نوقف السيرفر، نحاول مرة ثانية عند التعديل القادم
            print("[حفظ سحابي] فشل:", e, flush=True)


def _cloud_dirty():
    global _cloud_timer
    if not _cloud_enabled:
        return
    with _cloud_lock:
        if _cloud_timer is None:
            _cloud_timer = threading.Timer(1.5, _cloud_push)
            _cloud_timer.daemon = True
            _cloud_timer.start()


def _cloud_flush():
    if _cloud_enabled and _cloud_timer is not None:
        _cloud_timer.cancel()
        _cloud_push()


def _cloud_start():
    """عند الإقلاع: استعد القاعدة من السحابة. لو فشل نوقف الإقلاع بدل ما نكتب فوق نسخة سليمة بقاعدة فاضية."""
    global _cloud_enabled, _cloud_ver
    if not CLOUD_URL:
        return
    try:
        data, _cloud_ver = _cloud_load()
    except Exception as e:
        raise SystemExit(f"[حفظ سحابي] تعذر الاتصال بقاعدة DATABASE_URL: {e}")
    if data:
        _write_local(data)
        print(f"[حفظ سحابي] استُعيدت القاعدة ({len(data)} بايت)", flush=True)
    else:
        print("[حفظ سحابي] لا توجد نسخة سابقة، قاعدة جديدة", flush=True)
    _cloud_enabled = True
    atexit.register(_cloud_flush)


def _prepare_path():
    """ينشئ مجلد القاعدة لو ناقص. لو ما قدر (مسار غير قابل للكتابة) يرجع لمسار مؤقت مع تنبيه واضح."""
    global DB_PATH
    folder = os.path.dirname(DB_PATH) or "."
    try:
        os.makedirs(folder, exist_ok=True)
        probe = os.path.join(folder, ".rc_write_test")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
    except OSError as e:
        fallback = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses.db")
        print(f"[تنبيه] تعذر استخدام مسار القاعدة {DB_PATH} ({e}). استخدمت {fallback} — "
              "على الاستضافة هذا مؤقت وتنمسح الحسابات عند إعادة التشغيل! ركّب Disk واضبط RC_DB عليه.", flush=True)
        DB_PATH = fallback
    print(f"[قاعدة البيانات] {DB_PATH}", flush=True)


def init_db():
    _prepare_path()
    _cloud_start()
    with db() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS licenses(
                code TEXT PRIMARY KEY,
                channel TEXT NOT NULL,
                contact TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                agent_hash TEXT,
                phone_token_hash TEXT,
                pin_salt TEXT,
                pin_hash TEXT,
                phone_binds INTEGER NOT NULL DEFAULT 0,
                activated_at INTEGER
            )"""
        )
        have = {r["name"] for r in c.execute("PRAGMA table_info(licenses)")}
        for col in ("username", "pw_salt", "pw_hash", "agent_ip", "agent_name", "agent_token_hash"):
            if col not in have:
                c.execute(f"ALTER TABLE licenses ADD COLUMN {col} TEXT")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_license_username ON licenses(username)")
    _cloud_dirty()


# ---------------------------------------------------------------- تنسيق المدخلات
def normalize_code(raw):
    s = re.sub(r"\D", "", str(raw or "").translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")))
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
        return None  # أرقام الدول الثانية لازم تبدأ بـ +
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
            "UPDATE licenses SET channel=?, contact=? WHERE code=? AND contact=''",
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
        channel, contact = "", ""  # المشتري يسجّل جواله/إيميله بنفسه عند أول تفعيل
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
                    "VALUES(?,?,?,?,?,?)",
                    (code, channel, contact, note, now, expires),
                )
                return code
            except sqlite3.IntegrityError:
                continue
    raise RuntimeError("تعذر توليد كود فريد")


def get_license(code):
    with db() as c:
        row = c.execute("SELECT * FROM licenses WHERE code=?", (code,)).fetchone()
    return dict(row) if row else None


def list_licenses():
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM licenses ORDER BY created_at DESC")]


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
        cur = c.execute("UPDATE licenses SET status=? WHERE code=?", (status, code))
        return cur.rowcount > 0


def reset(code, what="all"):
    """يفك ربط الجهاز/الجوال (مثلاً المشتري غيّر كمبيوتره أو جواله)."""
    sets = []
    if what in ("agent", "all"):
        sets += ["agent_hash=NULL", "agent_ip=NULL", "agent_name=NULL", "agent_token_hash=NULL"]
    if what in ("phone", "all"):
        sets += ["phone_token_hash=NULL", "pin_salt=NULL", "pin_hash=NULL", "phone_binds=0"]
    if not sets:
        return False
    with db() as c:
        cur = c.execute(f"UPDATE licenses SET {', '.join(sets)} WHERE code=?", (code,))
        return cur.rowcount > 0


# ---------------------------------------------------------------- ربط الأجهزة
def bind_agent(code, machine_hash):
    with db() as c:
        c.execute(
            "UPDATE licenses SET agent_hash=? WHERE code=? AND agent_hash IS NULL",
            (machine_hash, code),
        )
        row = c.execute("SELECT agent_hash FROM licenses WHERE code=?", (code,)).fetchone()
    if not row:
        return False, "invalid"
    if hmac.compare_digest(row["agent_hash"] or "", machine_hash):
        return True, None
    return False, "device_mismatch"


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def hash_pin(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 100_000).hex()


def bind_phone(code, token, pin):
    salt = secrets.token_hex(8)
    with db() as c:
        row = c.execute("SELECT phone_binds FROM licenses WHERE code=?", (code,)).fetchone()
        if not row:
            return "invalid"
        if row["phone_binds"] >= MAX_PHONE_BINDS:
            return "rebind_limit"
        c.execute(
            "UPDATE licenses SET phone_token_hash=?, pin_salt=?, pin_hash=?, "
            "phone_binds=phone_binds+1, activated_at=COALESCE(activated_at, ?) WHERE code=?",
            (hash_token(token), salt, hash_pin(pin, salt), int(time.time()), code),
        )
    return "ok"


def check_token(row, token):
    h = row.get("phone_token_hash")
    return bool(h) and hmac.compare_digest(hash_token(token), h)


def check_pin(row, pin):
    if not row.get("pin_hash") or not row.get("pin_salt"):
        return False
    return hmac.compare_digest(hash_pin(pin, row["pin_salt"]), row["pin_hash"])


# ---------------------------------------------------------------- الحسابات (تسجيل ذاتي)
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,19}$")


def normalize_username(raw):
    u = str(raw or "").strip().lower()
    return u if USERNAME_RE.match(u) else None


def get_by_username(username):
    with db() as c:
        row = c.execute("SELECT * FROM licenses WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None


def get_by_contact(contact):
    with db() as c:
        row = c.execute(
            "SELECT * FROM licenses WHERE contact=? ORDER BY (username IS NULL) ASC LIMIT 1", (contact,)
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
                "UPDATE licenses SET username=?, pw_salt=?, pw_hash=? WHERE code=? AND username IS NULL",
                (username, salt, hash_pin(password, salt), code),
            )
            return "ok" if cur.rowcount else "exists"
    except sqlite3.IntegrityError:
        return "taken"


def check_password(row, password):
    """يقارن دائمًا (حتى لو المستخدم غير موجود) عشان ما يتسرّب وجوده بالزمن."""
    salt = (row or {}).get("pw_salt") or "00000000"
    expected = (row or {}).get("pw_hash") or ("0" * 64)
    ok = hmac.compare_digest(hash_pin(str(password), salt), expected)
    return bool(row) and bool(row.get("pw_hash")) and ok


def set_agent_info(code, ip, name):
    with db() as c:
        c.execute("UPDATE licenses SET agent_ip=?, agent_name=? WHERE code=?", (ip, name, code))


def set_agent_token(code, token):
    with db() as c:
        c.execute("UPDATE licenses SET agent_token_hash=? WHERE code=?", (hash_token(token), code))


def check_agent_token(row, token):
    h = row.get("agent_token_hash")
    return bool(h) and bool(token) and hmac.compare_digest(hash_token(str(token)), h)


def set_contact(code, channel, contact):
    with db() as c:
        c.execute("UPDATE licenses SET channel=?, contact=? WHERE code=?", (channel, contact, code))
