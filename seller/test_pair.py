# -*- coding: utf-8 -*-
"""اختبار ربط الكمبيوتر بكود (pair_request / pair_confirm) وتحميل البرنامج."""
import asyncio
import os

import test_license as T
from test_license import check, connect, rpc, signup, ldb, relay, TestClient, TestServer


async def phone_login(client, username, token, password="Passw0rd!"):
    ph = await connect(client)
    r = await rpc(ph, {"type": "login", "username": username, "password": password, "token": token})
    return ph, r


async def main():
    ldb.init_db()
    client = TestClient(TestServer(relay.make_app()))
    await client.start_server()
    try:
        r = await signup(client, "ali@mail.com", username="ali")
        tok = r["token"]
        ldb.set_status(ldb.get_by_username("ali")["code"], "active")
        relay.buckets.clear()
        ph, r = await phone_login(client, "ali", tok)
        check("الجوال دخل", r["type"] == "login_ok" and r["pc"]["online"] is False)

        # الكمبيوتر يطلب كود
        pc = await connect(client)
        r = await rpc(pc, {"type": "pair_request", "hwid": "HW-PC-ONE-1234", "name": "ALI-PC"})
        code = r.get("code", "")
        check("الكمبيوتر يستلم كود من 8 أرقام", r["type"] == "pair_code" and len(code) == 8 and code.isdigit())
        r = await rpc(pc, {"type": "pair_request", "hwid": "x"})
        check("بصمة جهاز قصيرة ترفض", r["reason"] == "bad_request")

        # جوال غير مسجّل دخول
        anon = await connect(client)
        r = await rpc(anon, {"type": "pair_confirm", "code": code})
        check("بدون تسجيل دخول يرفض", r["reason"] == "not_logged_in")
        await anon.close()

        wrong = "00000000" if code != "00000000" else "11111111"
        r = await rpc(ph, {"type": "pair_confirm", "code": wrong})
        check("كود خاطئ يرفض", r["reason"] == "bad_pair_code")
        r = await rpc(ph, {"type": "pair_confirm", "code": "12"})
        check("كود قصير يرفض", r["reason"] == "bad_pair_code")

        # الكود الصحيح (مع شرطة)
        pretty = code[:4] + "-" + code[4:]
        r = await rpc(ph, {"type": "pair_confirm", "code": pretty})
        check("الكود الصحيح يربط الجهاز", r["type"] == "pair_result" and r["ok"] and r["name"] == "ALI-PC")
        done = await pc.recv()
        check("الكمبيوتر يستلم المفتاح واسم المستخدم", done["type"] == "pair_done" and done["username"] == "ali" and len(done["agent_token"]) > 30)
        r = await rpc(pc, {"type": "register_agent", "username": "ali", "hwid": "HW-PC-ONE-1234", "name": "ALI-PC", "agent_token": done["agent_token"]})
        check("الكمبيوتر يسجّل دخول بالمفتاح", r["type"] == "registered_agent" and r["ok"])
        online = await ph.recv()
        check("الجوال يعرف إن الكمبيوتر اتصل", online["type"] == "agent_online")

        r = await rpc(ph, {"type": "pair_confirm", "code": code})
        check("الكود يُستخدم مرة وحدة", r["reason"] == "bad_pair_code")

        # كمبيوتر ثاني على نفس الحساب
        pc2 = await connect(client)
        r = await rpc(pc2, {"type": "pair_request", "hwid": "HW-PC-TWO-9999", "name": "OTHER"})
        r = await rpc(ph, {"type": "pair_confirm", "code": r["code"]})
        check("كمبيوتر ثاني على نفس الحساب يرفض", r["reason"] == "device_mismatch")
        await pc2.close()

        # إعادة ربط نفس الكمبيوتر مسموحة
        pc3 = await connect(client)
        r = await rpc(pc3, {"type": "pair_request", "hwid": "HW-PC-ONE-1234", "name": "ALI-PC"})
        r = await rpc(ph, {"type": "pair_confirm", "code": r["code"]})
        check("إعادة ربط نفس الكمبيوتر تنجح", r["ok"])
        await pc3.close()

        # كود منتهي
        pc4 = await connect(client)
        r = await rpc(pc4, {"type": "pair_request", "hwid": "HW-PC-ONE-1234", "name": "ALI-PC"})
        relay.pairs[r["code"]]["exp"] = 0
        r2 = await rpc(ph, {"type": "pair_confirm", "code": r["code"]})
        check("كود منتهي يرفض", r2["reason"] == "bad_pair_code")
        await pc4.close()

        # إغلاق الكمبيوتر يلغي الكود
        pc5 = await connect(client)
        r = await rpc(pc5, {"type": "pair_request", "hwid": "HW-PC-ONE-1234", "name": "ALI-PC"})
        await pc5.close(); await asyncio.sleep(0.2)
        check("الكود يُلغى لما يقفل البرنامج", r["code"] not in relay.pairs)

        # حد المحاولات الخاطئة
        relay.buckets.clear()
        for _ in range(5):
            await rpc(ph, {"type": "pair_confirm", "code": "99999999"})
        r = await rpc(ph, {"type": "pair_confirm", "code": "99999999"})
        check("تخمين الكود يُقفل بعد 5 محاولات", r["reason"] == "rate_limited")

        # حساب أُوقف بعد ما دخل الجوال: ما يقدر يربط جهاز
        relay.buckets.clear()
        ldb.set_status(ldb.get_by_username("ali")["code"], "revoked")
        pc6 = await connect(client)
        r = await rpc(pc6, {"type": "pair_request", "hwid": "HW-PC-ONE-1234", "name": "ALI-PC"})
        r = await rpc(ph, {"type": "pair_confirm", "code": r["code"]})
        check("حساب موقوف ما يربط", r["reason"] == "revoked")
        await pc6.close()
        await ph.close()
    finally:
        await client.close()

    # تحميل البرنامج
    client = TestClient(TestServer(relay.make_app()))
    await client.start_server()
    try:
        path = os.path.join(relay.BASE_DIR, "agent.exe")
        existed = os.path.exists(path)
        if not existed:
            resp = await client.get("/download/agent.exe")
            check("بدون ملف البرنامج: 404 برسالة واضحة", resp.status == 404)
            open(path, "wb").write(b"MZfake")
            try:
                resp = await client.get("/download/agent.exe")
                body = await resp.read()
                check("التحميل يشتغل", resp.status == 200 and body == b"MZfake" and "attachment" in resp.headers["Content-Disposition"])
            finally:
                os.remove(path)
    finally:
        await client.close()
    print(f"\nكل اختبارات الربط نجحت ({len(T.PASSED)} فحص بالمجموع)")


asyncio.run(main())
