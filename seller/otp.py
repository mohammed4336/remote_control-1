# -*- coding: utf-8 -*-
"""إرسال رمز التحقق (OTP) للمشتري — يستخدمه السيرفر الوسيط فقط.

الإعداد بمتغيرات البيئة (على سيرفرك، مو عند المشتري):

  SMS (رقم الجوال):
    SMS_PROVIDER=twilio     + TWILIO_SID, TWILIO_TOKEN, و (TWILIO_FROM أو TWILIO_MESSAGING_SID)
    SMS_PROVIDER=webhook    + SMS_WEBHOOK_URL (و SMS_WEBHOOK_AUTH اختياري)
                              يرسل POST JSON: {"to": "+966...", "message": "...", "otp": "123456"}
                              (تربطه بأي مزوّد رسائل سعودي: Unifonic, Taqnyat, Msegat ...)
    SMS_PROVIDER=console    (الافتراضي — للتجربة فقط: يطبع الرمز في شاشة السيرفر)

  الإيميل:
    SMTP_HOST, SMTP_PORT (587 أو 465), SMTP_USER, SMTP_PASS, SMTP_FROM
    بدون SMTP_HOST يطبع الرمز في شاشة السيرفر (للتجربة فقط).
"""

import asyncio
import os
import smtplib
from email.message import EmailMessage

import aiohttp


def _env(name, default=""):
    return os.environ.get(name, default).strip()


def describe():
    sms = _env("SMS_PROVIDER", "console").lower()
    email = "smtp" if _env("SMTP_HOST") else "console"
    return f"SMS={sms}  EMAIL={email}"


def is_dev_mode():
    return _env("SMS_PROVIDER", "console").lower() == "console" or not _env("SMTP_HOST")


def _message(otp):
    return f"رمز تفعيل لوحة التحكم عن بعد: {otp}\nصالح 10 دقائق. لا تشاركه مع أي أحد."


def _console(channel, contact, text):
    print("=" * 56)
    print(f"[DEV - لا تستخدمه في الإنتاج] {channel} -> {contact}")
    print(text)
    print("=" * 56, flush=True)


async def send_otp(channel, contact, otp):
    """يرسل الرمز أو يرمي استثناء لو فشل الإرسال."""
    text = _message(otp)
    if channel == "email":
        await _send_email(contact, text)
    else:
        await _send_sms(contact, text, otp)


# ---------------------------------------------------------------- إيميل
def _smtp_send(to, text):
    host = _env("SMTP_HOST")
    port = int(_env("SMTP_PORT", "587"))
    user, password = _env("SMTP_USER"), _env("SMTP_PASS")
    msg = EmailMessage()
    msg["From"] = _env("SMTP_FROM") or user
    msg["To"] = to
    msg["Subject"] = "رمز تفعيل لوحة التحكم عن بعد"
    msg.set_content(text)
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=20) as s:
            if user:
                s.login(user, password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls()
            if user:
                s.login(user, password)
            s.send_message(msg)


async def _send_email(to, text):
    if not _env("SMTP_HOST"):
        _console("email", to, text)
        return
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _smtp_send, to, text)


# ---------------------------------------------------------------- SMS
async def _send_sms(to, text, otp):
    provider = _env("SMS_PROVIDER", "console").lower()
    if provider == "twilio":
        await _twilio(to, text)
    elif provider == "webhook":
        await _webhook(to, text, otp)
    else:
        _console("sms", to, text)


async def _twilio(to, text):
    sid, token = _env("TWILIO_SID"), _env("TWILIO_TOKEN")
    data = {"To": to, "Body": text}
    if _env("TWILIO_MESSAGING_SID"):
        data["MessagingServiceSid"] = _env("TWILIO_MESSAGING_SID")
    else:
        data["From"] = _env("TWILIO_FROM")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        async with s.post(url, data=data, auth=aiohttp.BasicAuth(sid, token)) as r:
            if r.status >= 300:
                raise RuntimeError(f"Twilio HTTP {r.status}: {(await r.text())[:200]}")


async def _webhook(to, text, otp):
    url = _env("SMS_WEBHOOK_URL")
    headers = {}
    if _env("SMS_WEBHOOK_AUTH"):
        headers["Authorization"] = _env("SMS_WEBHOOK_AUTH")
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        async with s.post(url, json={"to": to, "message": text, "otp": otp}, headers=headers) as r:
            if r.status >= 300:
                raise RuntimeError(f"Webhook HTTP {r.status}: {(await r.text())[:200]}")
