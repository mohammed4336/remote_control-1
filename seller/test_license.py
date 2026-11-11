# -*- coding: utf-8 -*-
"""اختبار آلي لنظام التراخيص: تفعيل، ربط، منع المشاركة، إيقاف. يشغّل الوسيط داخل العملية."""
import asyncio
import json
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["RC_DB"] = os.path.join(_tmp, "t.db")
os.environ["ENFORCE_INTERVAL"] = "0.3"
os.environ["SIGNUP_MODE"] = "approval"

from aiohttp import WSMsgType  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

import licensedb as ldb  # noqa: E402
import otp as otpmod  # noqa: E402
import relay_server as relay  # noqa: E402

sent = []


async def fake_send(channel, contact, otp):
    sent.append((channel, contact, otp))


otpmod.send_otp = fake_send
PASSED = []


def check(name, cond):
    PASSED.append(name)
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        raise SystemExit(1)


class Peer:
    """يقرأ الرسائل بمهمة خلفية وينقلها لطابور (إلغاء receive في aiohttp يقفل الاتصال)."""

    def __init__(self, ws):
        self.ws = ws
        self.q = asyncio.Queue()
        self.task = asyncio.create_task(self._pump())

    async def _pump(self):
        try:
            async for m in self.ws:
                if m.type == WSMsgType.TEXT:
                    self.q.put_nowait(json.loads(m.data))
        finally:
            self.q.put_nowait({"type": "__closed__"})

    async def send_json(self, d):
        await self.ws.send_json(d)

    async def recv(self, timeout=3):
        return await asyncio.wait_for(self.q.get(), timeout)

    async def nothing(self, wait=0.5):
        await asyncio.sleep(wait)
        return self.q.empty()

    def drain(self):
        while not self.q.empty():
            self.q.get_nowait()

    async def close(self):
        await self.ws.close()


async def connect(client):
    return Peer(await client.ws_connect("/ws"))


async def rpc(ws, msg, timeout=3):
    await ws.send_json(msg)
    return await ws.recv(timeout)


async def signup(client, contact, secret="246810", username="ahmad", password="Passw0rd!", expect_status=None):
    """تسجيل كامل. يرجّع (token, status)."""
    ws = await connect(client)
    r = await rpc(ws, {"type": "signup_start", "contact": contact, "secret": secret})
    assert r["type"] == "otp_sent", r
    r = await rpc(ws, {"type": "signup_verify", "contact": contact, "otp": sent[-1][2]})
    assert r["type"] == "signup_verified", r
    r = await rpc(ws, {"type": "set_credentials", "setup_token": r["setup_token"], "username": username, "password": password})
    await ws.close()
    return r


async def main():
    ldb.init_db()
    server = TestServer(relay.make_app())
    client = TestClient(server)
    await client.start_server()
    try:
        # ---------- التسجيل
        ws = await connect(client)
        r = await rpc(ws, {"type": "signup_start", "contact": "not-valid", "secret": "246810"})
        check("جهة غير صالحة ترفض", r["reason"] == "bad_contact")
        r = await rpc(ws, {"type": "signup_start", "contact": "ahmad@mail.com", "secret": "12"})
        check("رقم سري غير 6 أرقام يرفض", r["reason"] == "bad_secret_format")
        r = await rpc(ws, {"type": "signup_start", "contact": "Ahmad@Mail.com", "secret": "246810"})
        check("الرمز يوصل للإيميل اللي كتبه الزبون", r["type"] == "otp_sent" and sent[-1][:2] == ("email", "ahmad@mail.com"))
        otp = sent[-1][2]
        r = await rpc(ws, {"type": "signup_start", "contact": "ahmad@mail.com", "secret": "246810"})
        check("طلب رمز ثاني فورًا يتأجل (cooldown)", r["reason"] == "cooldown")
        r = await rpc(ws, {"type": "signup_verify", "contact": "ahmad@mail.com", "otp": "000000"})
        check("رمز خاطئ يرفض", r["reason"] == "wrong_otp")
        r = await rpc(ws, {"type": "set_credentials", "setup_token": "x", "username": "ahmad", "password": "Passw0rd!"})
        check("إنشاء مستخدم بدون تحقق يرفض", r["reason"] == "setup_expired")
        r = await rpc(ws, {"type": "signup_verify", "contact": "ahmad@mail.com", "otp": otp})
        check("الرمز الصحيح يفتح خطوة إنشاء المستخدم", r["type"] == "signup_verified")
        st = r["setup_token"]
        r = await rpc(ws, {"type": "set_credentials", "setup_token": st, "username": "1bad name", "password": "Passw0rd!"})
        check("اسم مستخدم غير صالح يرفض", r["reason"] == "bad_username")
        r = await rpc(ws, {"type": "set_credentials", "setup_token": st, "username": "ahmad", "password": "short"})
        check("كلمة مرور قصيرة ترفض", r["reason"] == "bad_password")
        r = await rpc(ws, {"type": "set_credentials", "setup_token": st, "username": "Ahmad", "password": "Passw0rd!"})
        check("إنشاء الحساب نجح (بانتظار تفعيل البائع)", r["type"] == "account_ready" and r["status"] == "pending" and len(r["token"]) > 30)
        token = r["token"]
        await ws.close()

        relay.buckets.clear()
        ws = await connect(client)
        r = await rpc(ws, {"type": "signup_start", "contact": "ahmad@mail.com", "secret": "246810"})
        check("جهة مسجّلة مسبقًا ترفض (exists)", r["reason"] == "exists")
        await ws.close()
        relay.signups.clear()
        r = await signup(client, "0555123456", username="ahmad")
        check("اسم المستخدم المكرر يرفض", r["reason"] == "username_taken")

        # ---------- الدخول قبل التفعيل / بعده
        relay.buckets.clear()
        ph = await connect(client)
        r = await rpc(ph, {"type": "login", "username": "ahmad", "password": "wrong", "token": token})
        check("كلمة مرور خاطئة ترفض", r["reason"] == "bad_credentials")
        r = await rpc(ph, {"type": "login", "username": "nobody", "password": "Passw0rd!", "token": token})
        check("مستخدم غير موجود: نفس الرد (ما يتسرّب وجوده)", r["reason"] == "bad_credentials")
        r = await rpc(ph, {"type": "login", "username": "ahmad", "password": "Passw0rd!", "token": token})
        check("حساب بانتظار التفعيل ما يدخل", r["reason"] == "pending")
        ag = await connect(client)
        r = await rpc(ag, {"type": "register_agent", "username": "ahmad", "password": "Passw0rd!", "hwid": "PC-A"})
        check("برنامج الكمبيوتر ما يشتغل قبل التفعيل", r["reason"] == "pending")
        await ag.close()

        ldb.set_status(ldb.get_by_username("ahmad")["code"], "active")   # البائع فعّل بعد الدفع
        r = await rpc(ph, {"type": "login", "username": "ahmad", "password": "Passw0rd!", "token": token})
        check("بعد التفعيل: الجوال يدخل ويشوف جهازه (غير متصل)", r["type"] == "login_ok" and r["pc"]["online"] is False)

        # ---------- الكمبيوتر: ربط جهاز واحد
        ag = await connect(client)
        r = await rpc(ag, {"type": "register_agent", "username": "ahmad", "password": "bad", "hwid": "PC-A"})
        check("agent بكلمة مرور خاطئة يرفض", r["reason"] == "bad_credentials")
        r = await rpc(ag, {"type": "register_agent", "username": "ahmad", "password": "Passw0rd!", "hwid": "PC-A", "name": "DESKTOP-AHMAD"})
        check("agent على الكمبيوتر الأول ينربط ويستلم مفتاح جهاز", r["ok"] is True and r["agent_token"])
        agent_token = r["agent_token"]
        row = ldb.get_by_username("ahmad")
        check("سُجّل IP واسم الجهاز على الحساب", row["agent_ip"] and row["agent_name"] == "DESKTOP-AHMAD")
        r = await ph.recv()
        check("الجوال يُبلَّغ أن جهازه اتصل", r["type"] == "agent_online")
        ag2 = await connect(client)
        r = await rpc(ag2, {"type": "register_agent", "username": "ahmad", "password": "Passw0rd!", "hwid": "PC-B"})
        check("نفس الحساب على كمبيوتر ثاني يرفض (device_mismatch)", r["reason"] == "device_mismatch")
        r = await rpc(ag2, {"type": "register_agent", "username": "ahmad", "agent_token": agent_token, "hwid": "PC-B"})
        check("سرقة مفتاح الجهاز لكمبيوتر ثاني ما تنفع", r["reason"] == "device_mismatch")
        await ag2.close()

        # ---------- التحكم
        r = await rpc(ph, {"type": "connect_pc"})
        check("الجوال يوصّل على جهازه", r["type"] == "auth_result" and r["ok"] is True)
        r = await ag.recv()
        check("الـ agent يستلم إشعار اتصال الجوال", r == {"type": "controller", "connected": True})
        await ph.send_json({"type": "move", "dx": 5, "dy": 3})
        r = await ag.recv()
        check("أوامر الجوال توصل للكمبيوتر", r["type"] == "move" and r["dx"] == 5)
        await ag.send_json({"type": "frame", "data": "abc"})
        r = await ph.recv()
        check("بث الشاشة يوصل للجوال", r["type"] == "frame")
        await ag.send_json({"type": "login_ok"})
        check("الـ agent ما يقدر يرسل غير frame للجوال", await ph.nothing())

        stranger = await connect(client)
        await stranger.send_json({"type": "move", "dx": 1, "dy": 1})
        r = await rpc(stranger, {"type": "connect_pc"})
        check("بدون تسجيل دخول: ما يوصّل ولا يتحكم", r["reason"] == "bad_credentials" and await ag.nothing())
        await stranger.close()

        # ---------- مفتاح الجهاز يعيد الاتصال بدون كلمة المرور
        ag.drain()
        await ag.close()
        await asyncio.sleep(0.2)
        ag = await connect(client)
        r = await rpc(ag, {"type": "register_agent", "username": "ahmad", "agent_token": agent_token, "hwid": "PC-A"})
        check("إعادة اتصال الكمبيوتر بالمفتاح (بدون كلمة المرور)", r["ok"] is True and r["agent_token"] is None)
        ph.drain()

        # ---------- جوال جديد
        relay.buckets.clear()
        ph2 = await connect(client)
        r = await rpc(ph2, {"type": "login", "username": "ahmad", "password": "Passw0rd!", "token": ""})
        check("جوال جديد: يطلب رمز على جهة التسجيل", r["type"] == "need_otp" and sent[-1][:2] == ("email", "ahmad@mail.com"))
        otp2 = sent[-1][2]
        r = await rpc(ph2, {"type": "login_verify", "username": "ahmad", "password": "Passw0rd!", "otp": otp2, "secret": "999999"})
        check("الرقم السري الخاطئ يرفض", r["reason"] == "bad_secret")
        r = await rpc(ph2, {"type": "login_verify", "username": "ahmad", "password": "Passw0rd!", "otp": otp2, "secret": "246810"})
        check("جوال جديد بالرمز + الرقم السري ينربط", r["type"] == "login_ok" and r["token"] and r["pc"]["online"] is True)
        new_token = r["token"]
        got = None
        for _ in range(5):
            m = await ph.recv()
            if m["type"] in ("kicked", "__closed__"):
                got = m
                break
        check("الجوال القديم ينطرد", got is not None)
        relay.otp_state[ldb.get_by_username("ahmad")["code"]]["sent"] = []   # نتخطى فترة الانتظار بين الرموز
        ph3 = await connect(client)
        r = await rpc(ph3, {"type": "login", "username": "ahmad", "password": "Passw0rd!", "token": token})
        check("توكن الجوال القديم ما عاد يصلح (يطلب رمز)", r["type"] == "need_otp")
        r = await rpc(ph3, {"type": "login", "username": "ahmad", "password": "Passw0rd!", "token": new_token})
        check("توكن الجوال الجديد يشتغل بدون رمز", r["type"] == "login_ok")

        # ---------- إيقاف
        ldb.set_status(ldb.get_by_username("ahmad")["code"], "revoked")
        got = None
        for _ in range(6):
            m = await ph3.recv(3)
            if m["type"] == "license_ended":
                got = m
                break
        check("الإيقاف يقطع الجوال", got is not None)
        got = None
        for _ in range(6):
            m = await ag.recv(3)
            if m["type"] == "license_ended":
                got = m
                break
        check("الإيقاف يقطع الكمبيوتر", got is not None)
        ws = await connect(client)
        r = await rpc(ws, {"type": "login", "username": "ahmad", "password": "Passw0rd!", "token": new_token})
        check("حساب موقوف ما يدخل", r["reason"] == "revoked")
        await ws.close()

        # ---------- قفل التخمين
        relay.buckets.clear()
        relay.signups.clear()
        await signup(client, "0555999111", username="lockme", password="Passw0rd!")
        ws = await connect(client)
        for _ in range(5):
            r = await rpc(ws, {"type": "login", "username": "lockme", "password": "x" * 9, "token": ""})
        r = await rpc(ws, {"type": "login", "username": "lockme", "password": "Passw0rd!", "token": ""})
        check("بعد 5 محاولات خاطئة يتقفل حتى لو الباسورد صح", r["reason"] == "locked")
        await ws.close()

        # ---------- وضع التسجيل المفتوح
        relay.SIGNUP_MODE = "open"
        relay.buckets.clear()
        relay.signups.clear()
        r = await signup(client, "sara@mail.com", username="sara")
        check("الوضع المفتوح: الحساب فعّال فورًا", r["status"] == "active")

        check("0555 → +966", ldb.normalize_phone("0555123456") == "+966555123456")
        check("رقم أجنبي بدون + يرفض", ldb.normalize_phone("123456789012") is None)
    finally:
        await client.close()
    print(f"\nكل الاختبارات نجحت ({len(PASSED)})")


asyncio.run(main())
