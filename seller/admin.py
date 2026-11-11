# -*- coding: utf-8 -*-
"""أداة البائع لإدارة الحسابات — تشتغل على سيرفرك فقط (أو عن بعد عبر RC_ADMIN_URL).

الزبون يسجّل بنفسه من الموقع. أنت بس تفعّل حسابه بعد الدفع:

  python admin.py list                              # كل الحسابات (المعلّق أولًا)
  python admin.py show ahmad                        # تفاصيل حساب (باسم المستخدم)
  python admin.py approve ahmad --days 365          # تفعيل بعد الدفع (بدون --days = بدون انتهاء)
  python admin.py extend ahmad --days 30            # تمديد
  python admin.py revoke ahmad                      # إيقاف
  python admin.py restore ahmad                     # إعادة تشغيل
  python admin.py reset ahmad --what agent          # الزبون غيّر الكمبيوتر
  python admin.py reset ahmad --what phone          # فقد الجوال (يحتاج رمز على جهته)
  python admin.py contact ahmad --phone 0555123456  # غيّر جوال/إيميل التحقق
  python admin.py delete ahmad                      # حذف الحساب نهائيًا
"""

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
        print(
            f"{label(r):<16}{state(r):<16}"
            f"{ldb.mask_contact(r['channel'], r['contact']) if r['contact'] else '—':<26}"
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
        c.execute("UPDATE licenses SET status='active', expires_at=? WHERE code=?", (exp, r["code"]))
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
        c.execute("UPDATE licenses SET expires_at=? WHERE code=?", (new_exp, r["code"]))
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
        c.execute("DELETE FROM licenses WHERE code=?", (r["code"],))
    print("تم حذف الحساب.")


def remote(argv):
    url = os.environ["RC_ADMIN_URL"].rstrip("/") + "/admin/run"
    req = urllib.request.Request(
        url, data=json.dumps({"args": argv}).encode(),
        headers={"Authorization": "Bearer " + os.environ.get("RC_ADMIN_TOKEN", ""), "Content-Type": "application/json"},
    )
    try:
        r = json.load(urllib.request.urlopen(req, timeout=30))
    except Exception as e:
        sys.exit(f"فشل الاتصال بالسيرفر: {e}")
    print(r.get("output") or r.get("error"))
    sys.exit(0 if r.get("ok") else 1)


def main():
    if os.environ.get("RC_ADMIN_URL"):
        remote(sys.argv[1:])
    ldb.init_db()
    p = argparse.ArgumentParser(description="إدارة حسابات لوحة التحكم عن بعد")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list").set_defaults(fn=cmd_list)

    def with_who(name, **kw):
        sp = sub.add_parser(name)
        sp.add_argument("who", help="اسم المستخدم (أو الرقم الداخلي)")
        return sp

    with_who("show").set_defaults(fn=cmd_show)
    ap = with_who("approve"); ap.add_argument("--days", type=int); ap.set_defaults(fn=cmd_approve)
    with_who("revoke").set_defaults(fn=lambda a: cmd_status(a, "revoked", "تم إيقاف الحساب (يفصل خلال نصف دقيقة)."))
    with_who("restore").set_defaults(fn=lambda a: cmd_status(a, "active", "تم إعادة تشغيل الحساب."))
    rt = with_who("reset"); rt.add_argument("--what", choices=["agent", "phone", "all"], default="all"); rt.set_defaults(fn=cmd_reset)
    ex = with_who("extend"); ex.add_argument("--days", type=int, required=True); ex.set_defaults(fn=cmd_extend)
    ct = with_who("contact"); ct.add_argument("--phone"); ct.add_argument("--email"); ct.set_defaults(fn=cmd_contact)
    with_who("delete").set_defaults(fn=cmd_delete)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
