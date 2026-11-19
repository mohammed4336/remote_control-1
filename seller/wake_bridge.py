# -*- coding: utf-8 -*-
"""Account-scoped LAN Wake-on-LAN bridge. Pair once with a token from the dashboard."""
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import re
import socket

import aiohttp

DEFAULT_RELAY = "https://remote-control-by-akira.onrender.com"
MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def config_path():
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
    folder = Path(root) / "RemoteControl"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "wake-bridge.json"


def load_token():
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
        token = str(data.get("token", "")).strip()
        return token if len(token) >= 32 else ""
    except Exception:
        return ""


def save_token(token):
    path = config_path()
    path.write_text(json.dumps({"token": token}), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def forget_token():
    try:
        config_path().unlink()
    except OSError:
        pass


def ask_token():
    print("\nافتح موقع تحكم بعيد > إنشاء رمز ربط الوسيط.")
    token = input("الصق رمز الربط هنا ثم اضغط Enter: ").strip()
    if len(token) < 32:
        raise SystemExit("رمز الربط غير صالح. أنشئ رمزًا جديدًا من الموقع.")
    save_token(token)
    return token


def send_magic_packet(mac, broadcast):
    if not MAC_RE.fullmatch(mac):
        raise ValueError("invalid_mac")
    ipaddress.IPv4Address(broadcast)
    raw = bytes.fromhex(mac.replace(":", ""))
    packet = b"\xff" * 6 + raw * 16
    for port in (9, 7):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2)
            sock.sendto(packet, (broadcast, port))
        finally:
            sock.close()
    return True


async def run():
    print("=" * 58)
    print("Remote Control - Wake Bridge")
    print("هذا هو الوسيط المركزي للموقع. يجب أن يبقى شغالًا ومتصلًا بالإنترنت.")
    print("الإيقاظ يحتاج أن تكون شبكة الهدف على نفس LAN أو VPN يمرر broadcast.")
    print("=" * 58)

    token = load_token() or ask_token()
    url = "wss://" + DEFAULT_RELAY[8:].rstrip("/") + "/ws"
    delay = 3

    while True:
        try:
            timeout = aiohttp.ClientTimeout(total=None, sock_connect=15, sock_read=None)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(url, heartbeat=20, max_msg_size=1024 * 1024) as ws:
                    await ws.send_json({"type": "register_wake_bridge", "token": token})
                    first = await ws.receive(timeout=20)
                    if first.type != aiohttp.WSMsgType.TEXT:
                        raise RuntimeError("لم يصل رد التسجيل من الخادم")
                    reply = json.loads(first.data)
                    if reply.get("type") != "wake_bridge_registered" or not reply.get("ok"):
                        reason = str(reply.get("reason", "unknown"))
                        if reason == "invalid_bridge_token":
                            forget_token()
                            raise ValueError("انتهت صلاحية رمز الربط أو أُلغي. افتح الموقع وأنشئ رمزًا جديدًا.")
                        raise RuntimeError("فشل التسجيل: " + reason)

                    print("[OK] تم ربط الوسيط المركزي بالموقع. ينتظر أوامر جميع الحسابات...")
                    print("يمكنك إغلاق هذه النافذة فقط إذا أردت إيقاف وسيط التشغيل.")
                    delay = 3

                    async for raw in ws:
                        if raw.type != aiohttp.WSMsgType.TEXT:
                            continue
                        try:
                            msg = json.loads(raw.data)
                        except Exception:
                            continue
                        if msg.get("type") != "wake_pc":
                            continue
                        try:
                            send_magic_packet(
                                str(msg.get("mac", "")),
                                str(msg.get("broadcast", "255.255.255.255")),
                            )
                            await ws.send_json({
                                "type": "wake_result", "ok": True,
                                "request_id": msg.get("request_id", "")
                            })
                            print("[OK] تم إرسال إشارة التشغيل.")
                        except Exception as exc:
                            await ws.send_json({
                                "type": "wake_result",
                                "ok": False,
                                "reason": str(exc)[:80],
                                "request_id": msg.get("request_id", ""),
                            })
        except KeyboardInterrupt:
            break
        except ValueError as exc:
            print("[Bridge]", str(exc))
            token = ask_token()
            delay = 3
        except Exception as exc:
            print("[Bridge] تعذر الاتصال:", str(exc)[:180])
            print("[Bridge] إعادة المحاولة بعد", delay, "ثوانٍ...")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nتم إيقاف Wake Bridge.")
