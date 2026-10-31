from pathlib import Path
import zipfile, ast

out = Path("/mnt/data/remote_control_postgres_update")
out.mkdir(exist_ok=True)

licensedb = r'''# -*- coding: utf-8 -*-
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
        prepare_threshold=None,
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
        for col in ("username", "pw_salt", "pw_hash", "agent_ip", "agent_name", "agent_token_hash"):
            c.execute(f"ALTER TABLE licenses ADD COLUMN IF NOT EXISTS {col} TEXT")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_license_username ON licenses(username)")


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
        return None
    if not 10 <= len(d) <= 15:
        return None
    return "+" + d


def parse_contact(raw):
    s = str(raw or "").strip()
    if "@" in s:
        s = s.lower()
        return ("email", s) if EMAIL_RE.match(s) and len(s) <= 120 else None
    p = normalize_phone(s)
    return ("sms", p) if p else None


def claim_contact(code, channel, contact):
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
        for _ in range(30):
            code = "".join(secrets.choice("0123456789") for _ in range(6))
            row = c.execute(
                """INSERT INTO licenses(code,channel,contact,note,created_at,expires_at)
                   VALUES(%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (code) DO NOTHING
                   RETURNING code""",
                (code, channel, contact, note, now, expires),
            ).fetchone()
            if row:
                return row["code"]
    raise RuntimeError("تعذر توليد كود فريد")


def get_license(code):
    with db() as c:
        row = c.execute("SELECT * FROM licenses WHERE code=%s", (code,)).fetchone()
    return dict(row) if row else None


def list_licenses():
    with db() as c:
        rows = c.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


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
        cur = c.execute("UPDATE licenses SET status=%s WHERE code=%s", (status, code))
        return cur.rowcount > 0


def reset(code, what="all"):
    sets = []
    if what in ("agent", "all"):
        sets += ["agent_hash=NULL", "agent_ip=NULL", "agent_name=NULL", "agent_token_hash=NULL"]
    if what in ("phone", "all"):
        sets += ["phone_token_hash=NULL", "pin_salt=NULL", "pin_hash=NULL", "phone_binds=0"]
    if not sets:
        return False
    with db() as c:
        cur = c.execute(f"UPDATE licenses SET {', '.join(sets)} WHERE code=%s", (code,))
        return cur.rowcount > 0


def bind_agent(code, machine_hash):
    with db() as c:
        c.execute(
            "UPDATE licenses SET agent_hash=%s WHERE code=%s AND agent_hash IS NULL",
            (machine_hash, code),
        )
        row = c.execute("SELECT agent_hash FROM licenses WHERE code=%s", (code,)).fetchone()
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
        row = c.execute("SELECT phone_binds FROM licenses WHERE code=%s", (code,)).fetchone()
        if not row:
            return "invalid"
        if row["phone_binds"] >= MAX_PHONE_BINDS:
            return "rebind_limit"
        c.execute(
            "UPDATE licenses SET phone_token_hash=%s, pin_salt=%s, pin_hash=%s, "
            "phone_binds=phone_binds+1, activated_at=COALESCE(activated_at, %s) WHERE code=%s",
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


USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,19}$")


def normalize_username(raw):
    u = str(raw or "").strip().lower()
    return u if USERNAME_RE.match(u) else None


def get_by_username(username):
    with db() as c:
        row = c.execute("SELECT * FROM licenses WHERE username=%s", (username,)).fetchone()
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
    ident = str(ident or "").strip()
    code = normalize_code(ident)
    row = get_license(code) if code else None
    return row or get_by_username(ident.lower())


def set_credentials(code, username, password):
    salt = secrets.token_hex(8)
    with db() as c:
        cur = c.execute(
            "UPDATE licenses SET username=%s, pw_salt=%s, pw_hash=%s "
            "WHERE code=%s AND username IS NULL",
            (username, salt, hash_pin(password, salt), code),
        )
        return "ok" if cur.rowcount else "exists"


def check_password(row, password):
    salt = (row or {}).get("pw_salt") or "00000000"
    expected = (row or {}).get("pw_hash") or ("0" * 64)
    ok = hmac.compare_digest(hash_pin(str(password), salt), expected)
    return bool(row) and bool(row.get("pw_hash")) and ok


def set_agent_info(code, ip, name):
    with db() as c:
        c.execute("UPDATE licenses SET agent_ip=%s, agent_name=%s WHERE code=%s", (ip, name, code))


def set_agent_token(code, token):
    with db() as c:
        c.execute("UPDATE licenses SET agent_token_hash=%s WHERE code=%s", (hash_token(token), code))


def check_agent_token(row, token):
    h = row.get("agent_token_hash")
    return bool(h) and bool(token) and hmac.compare_digest(hash_token(str(token)), h)


def set_contact(code, channel, contact):
    with db() as c:
        c.execute("UPDATE licenses SET channel=%s, contact=%s WHERE code=%s", (channel, contact, code))
'''

admin = r'''# -*- coding: utf-8 -*-
"""أداة البائع لإدارة الحسابات — تعمل محلياً أو عبر RC_ADMIN_URL."""

import argparse
import json
import os
import sys
import time
import urllib.request

import licensedb as ldb


def fmt_ts(ts):
    return time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else "—"


def state(row):
    ok, reason = ldb.usable(row)
    if not ok:
        return {"pending": "بانتظار التفعيل", "revoked": "موقوف", "expired": "منتهي"}.get(reason, reason)
    return "فعّال"


def need(ident):
    row = ldb.find(ident)
    if not row:
        sys.exit("الحساب غير موجود: " + str(ident))
    return row


def label(r):
    return r.get("username") or f"(بدون اسم — {r['code']})"


def cmd_list(_a):
    rows = ldb.list_licenses()
    if not rows:
        print("لا توجد حسابات.")
        return
    rows.sort(key=lambda r: (ldb.usable(r)[1] != "pending", -r["created_at"]))
    print(f"{'المستخدم':<16}{'الحالة':<16}{'الجهة':<26}{'كمبيوتر':<9}{'ينتهي':<12}")
    for r in rows:
        contact = ldb.mask_contact(r["channel"], r["contact"]) if r["contact"] else "—"
        print(
            f"{label(r):<16}{state(r):<16}{contact:<26}"
            f"{'نعم' if r['agent_hash'] else 'لا':<9}{fmt_ts(r['expires_at']):<12}"
        )


def cmd_show(a):
    r = need(a.who)
    print(f"المستخدم        : {label(r)}")
    print(f"الرقم الداخلي    : {r['code']}")
    print(f"الحالة          : {state(r)}")
    print(f"جهة التحقق      : {r['channel']} -> {ldb.mask_contact(r['channel'], r['contact'])}")
    print(f"أُنشئ           : {fmt_ts(r['created_at'])}")
    print(f"عدد ربط الجوال   : {r['phone_binds']}/{ldb.MAX_PHONE_BINDS}")
    print(f"مربوط بكمبيوتر   : {'نعم' if r['agent_hash'] else 'لا'}  (IP آخر اتصال: {r.get('agent_ip') or '—'}  الاسم: {r.get('agent_name') or '—'})")
    print(f"ينتهي           : {fmt_ts(r['expires_at']) if r['expires_at'] else 'بدون انتهاء'}")


def cmd_approve(a):
    r = need(a.who)
    exp = int(time.time()) + a.days * 86400 if a.days else None
    with ldb.db() as c:
        c.execute(
            "UPDATE licenses SET status='active', expires_at=%s WHERE code=%s",
            (exp, r["code"]),
        )
    print(f"تم تفعيل {label(r)} ✅  ينتهي: {fmt_ts(exp) if exp else 'بدون انتهاء'}")


def cmd_status(a, status, msg):
    r = need(a.who)
    ldb.set_status(r["code"], status)
    print(msg)


def cmd_reset(a):
    r = need(a.who)
    ldb.reset(r["code"], a.what)
    print(f"تم فك الربط ({a.what}) — الزبون يقدر يربط من جديد.")


def cmd_extend(a):
    r = need(a.who)
    base = max(int(time.time()), r["expires_at"] or 0)
    new_exp = base + a.days * 86400
    with ldb.db() as c:
        c.execute("UPDATE licenses SET expires_at=%s WHERE code=%s", (new_exp, r["code"]))
    print("ينتهي الآن:", fmt_ts(new_exp))


def cmd_contact(a):
    r = need(a.who)
    if bool(a.phone) == bool(a.email):
        sys.exit("حدد --phone أو --email (واحد فقط)")
    parsed = ldb.parse_contact(a.phone or a.email)
    if not parsed:
        sys.exit("الجوال/الإيميل غير صالح")
    ldb.set_contact(r["code"], *parsed)
    ldb.reset(r["code"], "phone")
    print("تم تغيير جهة التحقق، والزبون يحتاج يدخل من جديد على جواله.")


def cmd_delete(a):
    r = need(a.who)
    with ldb.db() as c:
        c.execute("DELETE FROM licenses WHERE code=%s", (r["code"],))
    print("تم حذف الحساب.")


def remote(argv):
    url = os.environ["RC_ADMIN_URL"].rstrip("/") + "/admin/run"
    req = urllib.request.Request(
        url,
        data=json.dumps({"args": argv}).encode(),
        headers={
            "Authorization": "Bearer " + os.environ.get("RC_ADMIN_TOKEN", ""),
            "Content-Type": "application/json",
        },
    )
    try:
        result = json.load(urllib.request.urlopen(req, timeout=30))
    except Exception as e:
        sys.exit(f"فشل الاتصال بالسيرفر: {e}")
    print(result.get("output") or result.get("error"))
    sys.exit(0 if result.get("ok") else 1)


def main():
    if os.environ.get("RC_ADMIN_URL"):
        remote(sys.argv[1:])
    ldb.init_db()
    p = argparse.ArgumentParser(description="إدارة حسابات لوحة التحكم عن بعد")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)

    def with_who(name):
        sp = sub.add_parser(name)
        sp.add_argument("who", help="اسم المستخدم (أو الرقم الداخلي)")
        return sp

    with_who("show").set_defaults(fn=cmd_show)
    ap = with_who("approve")
    ap.add_argument("--days", type=int)
    ap.set_defaults(fn=cmd_approve)
    with_who("revoke").set_defaults(
        fn=lambda a: cmd_status(a, "revoked", "تم إيقاف الحساب (يفصل خلال نصف دقيقة).")
    )
    with_who("restore").set_defaults(
        fn=lambda a: cmd_status(a, "active", "تم إعادة تشغيل الحساب.")
    )
    rt = with_who("reset")
    rt.add_argument("--what", choices=["agent", "phone", "all"], default="all")
    rt.set_defaults(fn=cmd_reset)
    ex = with_who("extend")
    ex.add_argument("--days", type=int, required=True)
    ex.set_defaults(fn=cmd_extend)
    ct = with_who("contact")
    ct.add_argument("--phone")
    ct.add_argument("--email")
    ct.set_defaults(fn=cmd_contact)
    with_who("delete").set_defaults(fn=cmd_delete)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
'''

(out / "licensedb.py").write_text(licensedb, encoding="utf-8")
(out / "admin.py").write_text(admin, encoding="utf-8")
(out / "requirements.txt").write_text("aiohttp>=3.9\npsycopg[binary]>=3.2\n", encoding="utf-8")

ast.parse(licensedb)
ast.parse(admin)

zip_path = Path("/mnt/data/remote_control_postgres_update.zip")
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for name in ("licensedb.py", "admin.py", "requirements.txt"):
        z.write(out / name, arcname=name)

print("تم إنشاء الملفات وفحص صياغة Python بنجاح.")
print(zip_path)
