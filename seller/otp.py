from pathlib import Path

content = r'''# -*- coding: utf-8 -*-
"""إرسال رمز التحقق (OTP) للمشتري — يستخدمه السيرفر الوسيط فقط.

إعدادات البريد:
  BREVO_API_KEY  مفتاح API من Brevo (مفضّل على Render المجاني)
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM  (اختياري كبديل)

إعدادات SMS:
  SMS_PROVIDER=twilio + TWILIO_SID, TWILIO_TOKEN, و (TWILIO_FROM أو TWILIO_MESSAGING_SID)
  SMS_PROVIDER=webhook + SMS_WEBHOOK_URL (و SMS_WEBHOOK_AUTH اختياري)
  SMS_PROVIDER=console (الافتراضي — يطبع الرمز في سجل السيرفر)
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
    if _env("BREVO_API_KEY"):
        email = "brevo_api"
    elif _env("SMTP_HOST"):
        email = "smtp"
    else:
        email = "console"
    return f"SMS={sms}  EMAIL={email}"


def is_dev_mode():
    # وضع التجربة للبريد فقط؛ وجود SMS_PROVIDER=console لا يعطّل إرسال البريد.
    return not (_env("BREVO_API_KEY") or _env("SMTP_HOST"))


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


# ---------------------------------------------------------------- إيميل عبر Brevo API
async def _brevo_send(to, text):
    api_key = _env("BREVO_API_KEY")
    sender = _env("SMTP_FROM")
    if not api_key:
        raise RuntimeError("BREVO_API_KEY غير مضبوط")
    if not sender:
        raise RuntimeError("SMTP_FROM غير مضبوط: أضف بريد المرسل الموثّق في Brevo")

    payload = {
        "sender": {"name": "Akira", "email": sender},
        "to": [{"email": to}],
        "subject": "رمز تفعيل لوحة التحكم عن بعد",
        "textContent": text,
    }
    headers = {
        "api-key": api_key,
        "accept": "application/json",
        "content-type": "application/json",
    }
    timeout = aiohttp.ClientTimeout(total=25)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            "https://api.brevo.com/v3/smtp/email",
            json=payload,
            headers=headers,
        ) as response:
            if response.status >= 300:
                details = (await response.text())[:500]
                raise RuntimeError(f"Brevo API HTTP {response.status}: {details}")


# ---------------------------------------------------------------- إيميل عبر SMTP (بديل)
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
        with smtplib.SMTP_SSL(host, port, timeout=20) as server:
            if user:
                server.login(user, password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as server:
            server.starttls()
            if user:
                server.login(user, password)
            server.send_message(msg)


async def _send_email(to, text):
    # Brevo API أولاً؛ لا يستخدم SMTP عند وجود مفتاح API.
    if _env("BREVO_API_KEY"):
        await _brevo_send(to, text)
        return

    if _env("SMTP_HOST"):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _smtp_send, to, text)
        return

    _console("email", to, text)


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
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, data=data, auth=aiohttp.BasicAuth(sid, token)) as response:
            if response.status >= 300:
                raise RuntimeError(f"Twilio HTTP {response.status}: {(await response.text())[:200]}")


async def _webhook(to, text, otp):
    url = _env("SMS_WEBHOOK_URL")
    headers = {}
    if _env("SMS_WEBHOOK_AUTH"):
        headers["Authorization"] = _env("SMS_WEBHOOK_AUTH")
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            url,
            json={"to": to, "message": text, "otp": otp},
            headers=headers,
        ) as response:
            if response.status >= 300:
                raise RuntimeError(f"Webhook HTTP {response.status}: {(await response.text())[:200]}")
'''

path = Path("/mnt/data/otp.py")
print(f"تم إنشاء الملف: {path}")
def describe():
    email = "brevo_api" if os.getenv("BREVO_API_KEY") else (
        "smtp" if os.getenv("SMTP_HOST") else "console"
    )
    sms = os.getenv("SMS_PROVIDER", "console")
    return f"SMS={sms} EMAIL={email}"
