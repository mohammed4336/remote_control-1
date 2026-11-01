# -*- coding: utf-8 -*-
"""اختبار لوحة البائع: دخول، قائمة، تفعيل، تمديد، إيقاف، حماية."""
import asyncio, os, tempfile
_tmp = tempfile.mkdtemp()
os.environ["RC_DB"] = os.path.join(_tmp, "s.db")
os.environ["SELLER_USERNAME"] = "boss"
os.environ["SELLER_PASSWORD"] = "S3cret-pass!"
from aiohttp.test_utils import TestClient, TestServer
import licensedb as ldb
import relay_server as relay


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        raise SystemExit(1)


async def main():
    ldb.init_db()
    code = ldb.create_license("email", "a@b.com", "t")
    ldb.set_status(code, "pending")
    ldb.set_credentials(code, "akira", "Passw0rd!")
    client = TestClient(TestServer(relay.make_app()))
    await client.start_server()
    try:
        r = await client.get("/seller")
        check("بدون دخول: صفحة تسجيل الدخول", r.status == 200 and "دخول البائع" in await r.text())
        r = await client.get("/seller/api/licenses")
        check("API بدون دخول يرفض (401)", r.status == 401)
        r = await client.post("/seller/login", json={"username": "boss", "password": "wrong"})
        check("كلمة سر خاطئة ترفض", r.status == 401)
        r = await client.post("/seller/login", json={"username": "boss", "password": "S3cret-pass!"}, headers={"Origin": "https://evil.com"})
        check("طلب دخول من موقع ثاني يرفض (CSRF)", r.status == 403)
        r = await client.post("/seller/login", json={"username": "boss", "password": "S3cret-pass!"})
        check("الدخول الصحيح ينجح ويضع كوكي", r.status == 200 and "rc_seller" in r.headers.get("Set-Cookie", "") and "HttpOnly" in r.headers["Set-Cookie"])
        r = await client.get("/seller")
        check("بعد الدخول: تظهر لوحة البائع", "لوحة البائع" in await r.text() and "stTotal" in await r.text())
        r = await client.get("/seller/api/licenses")
        d = await r.json()
        row = d["licenses"][0]
        check("القائمة فيها الحساب بجهة مخفية وبدون كلمة مرور", row["username"] == "akira" and "***" in row["masked_contact"] and "pw_hash" not in row and "contact" not in row)
        r = await client.post(f"/seller/api/licenses/{code}/activate", json={"days": 30})
        check("تفعيل 30 يوم", r.status == 200 and ldb.usable(ldb.get_license(code))[0])
        exp1 = ldb.get_license(code)["expires_at"]
        r = await client.post(f"/seller/api/licenses/{code}/extend", json={"days": 10})
        check("تمديد 10 أيام يضاف للانتهاء", ldb.get_license(code)["expires_at"] == exp1 + 10 * 86400)
        r = await client.post(f"/seller/api/licenses/{code}/activate", json={"days": 0})
        check("أيام غير صالحة ترفض", r.status == 400)
        r = await client.post(f"/seller/api/licenses/{code}/activate", json={"days": 5}, headers={"Origin": "https://evil.com"})
        check("إجراء من موقع ثاني يرفض (CSRF)", r.status == 403)
        r = await client.post(f"/seller/api/licenses/{code}/revoke", json={})
        check("إيقاف", r.status == 200 and ldb.get_license(code)["status"] == "revoked")
        r = await client.post(f"/seller/api/licenses/{code}/restore", json={})
        check("إعادة تشغيل", r.status == 200 and ldb.get_license(code)["status"] == "active")
        ldb.bind_agent(code, "hw")
        r = await client.post(f"/seller/api/licenses/{code}/reset_agent", json={})
        check("فك ربط الجهاز", r.status == 200 and not ldb.get_license(code)["agent_hash"])
        ldb.bind_phone(code, "tok", "123456")
        r = await client.post(f"/seller/api/licenses/{code}/reset_phone", json={})
        check("فك ربط الجوال", r.status == 200 and not ldb.get_license(code)["phone_token_hash"])
        r = await client.post("/seller/api/licenses/999999/revoke", json={})
        check("حساب غير موجود 404", r.status == 404)
        r = await client.post("/seller/api/licenses/" + code + "/explode", json={})
        check("إجراء غير معروف 404", r.status == 404)
        r = await client.post("/seller/logout", json={})
        r = await client.get("/seller/api/licenses")
        check("بعد الخروج: الجلسة تنتهي (401)", r.status == 401)
        await client.post("/seller/login", json={"username": "boss", "password": "S3cret-pass!"})
        r = await client.post("/seller/api/licenses/" + code + "/delete", json={})
        check("حذف الحساب", r.status == 200 and ldb.get_license(code) is None)
        for _ in range(6):
            await client.post("/seller/login", json={"username": "boss", "password": "x"})
        r = await client.post("/seller/login", json={"username": "boss", "password": "S3cret-pass!"})
        check("بعد 5 محاولات خاطئة يتقفل الدخول (429)", r.status == 429)
        relay.SELLER_PASS = ""
        r = await client.get("/seller")
        check("بدون إعداد SELLER_*: اللوحة مقفولة (404)", r.status == 404)
    finally:
        await client.close()
    print("\nكل اختبارات لوحة البائع نجحت")

asyncio.run(main())
