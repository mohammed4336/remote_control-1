
# -*- coding: utf-8 -*-
"""
Agent - يشتغل على كمبيوتر العميل (Windows) وينفّذ أوامر الجوال.

أول تشغيل: يسأل عن كود الترخيص ويحفظه بجانب البرنامج (agent_config.json).
بعدها يكفي دبل كليك على agent.exe.

الاستخدام اليدوي: python agent.py [رابط_الموقع] [كود_الترخيص]
"""

import asyncio
import base64
import ctypes
import io
import getpass
import json
import platform
import os
import sys
import subprocess
from ctypes import wintypes

import aiohttp
import pyautogui
from PIL import Image, ImageDraw, ImageGrab

try:
    ctypes.windll.user32.SetProcessDPIAware()
except Exception:
    pass

pyautogui.FAILSAFE = False
pyautogui.PAUSE = 0

BASE_DIR = (
    os.path.dirname(sys.executable)
    if getattr(sys, "frozen", False)
    else os.path.dirname(os.path.abspath(__file__))
)

CONFIG_PATH = os.path.join(BASE_DIR, "agent_config.json")
DEFAULT_RELAY = "https://remote-control-by-akira.onrender.com"

streaming = {"on": False}
flow = {"sent": [], "rtt": 0.0}

# ---------- Unicode keyboard input ----------

KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
ULONG_PTR = ctypes.c_size_t


class _KI(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class _MI(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class _IU(ctypes.Union):
    _fields_ = [
        ("ki", _KI),
        ("mi", _MI),
    ]


class _INPUT(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("u", _IU),
    ]


def type_unicode(text):
    """يكتب النص حرفًا حرفًا كما هو، ويدعم العربية."""
    for ch in text:
        if ch in "\r\n":
            if ch == "\n":
                pyautogui.press("enter")
            continue

        data = ch.encode("utf-16-le")

        for i in range(0, len(data), 2):
            unit = int.from_bytes(data[i:i + 2], "little")
            events = []

            for flags in (
                KEYEVENTF_UNICODE,
                KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
            ):
                inp = _INPUT(type=1)
                inp.u.ki = _KI(0, unit, flags, 0, 0)
                events.append(inp)

            arr = (_INPUT * 2)(*events)
            ctypes.windll.user32.SendInput(
                2, arr, ctypes.sizeof(_INPUT)
            )


def draw_cursor(img, scale):
    """يرسم مؤشر الماوس فوق صورة الشاشة."""
    try:
        pt = wintypes.POINT()
        ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))

        x, y = pt.x * scale, pt.y * scale

        if not (0 <= x < img.size[0] and 0 <= y < img.size[1]):
            return

        arrow = [
            (0, 0), (0, 17), (4, 13),
            (7, 20), (10, 19), (7, 12), (12, 12)
        ]

        d = ImageDraw.Draw(img)
        d.polygon(
            [(x + a, y + b) for a, b in arrow],
            fill="white",
            outline="black",
        )

    except Exception:
        pass


def power_action(action):
    """إطفاء أو إعادة تشغيل أو سكون."""
    if action == "sleep":
        ok = ctypes.windll.powrprof.SetSuspendState(0, 1, 0)
        print("Sleep requested" if ok else "Sleep failed")
        return

    flag = {
        "shutdown": "/s",
        "restart": "/r",
    }.get(action)

    if not flag:
        return

    r = subprocess.run(
        ["shutdown", flag, "/f", "/t", "0"],
        capture_output=True,
        text=True,
    )

    print(
        f"{action}:",
        "OK" if r.returncode == 0 else (r.stderr or r.stdout).strip()
    )


KEY_MAP = {
    "enter": "enter",
    "backspace": "backspace",
    "space": "space",
    "tab": "tab",
    "esc": "esc",
    "up": "up",
    "down": "down",
    "left": "left",
    "right": "right",
}

MEDIA_MAP = {
    "volume_up": "volumeup",
    "volume_down": "volumedown",
    "mute": "volumemute",
    "play_pause": "playpause",
    "next": "nexttrack",
    "prev": "prevtrack",
}

REASONS = {
    "bad_credentials": "Wrong username or password.",
    "revoked": "This account was suspended. Contact the seller.",
    "expired": "This account has expired. Contact the seller.",
    "pending": "Your account is waiting for the seller to activate it. Retrying every 30 seconds...",
    "device_mismatch": "This account is already linked to another computer. Contact the seller to move it.",
    "locked": "Too many wrong attempts. Try again in 15 minutes.",
    "rate_limited": "Too many attempts. Wait a few minutes.",
    "bad_request": "Could not request a pairing code.",
}

FATAL = {
    "bad_credentials",
    "revoked",
    "expired",
    "device_mismatch",
    "locked",
}


def handle_command(msg: dict):
    t = msg.get("type")

    if t == "move":
        pyautogui.moveRel(
            float(msg.get("dx", 0)),
            float(msg.get("dy", 0)),
            duration=0,
        )

    elif t == "click":
        button = msg.get("button", "left")

        if button not in ("left", "right", "middle"):
            return

        if msg.get("double"):
            pyautogui.doubleClick(button=button)
        else:
            pyautogui.click(button=button)

    elif t == "scroll":
        pyautogui.scroll(int(msg.get("dy", 0)))

    elif t == "key":
        key = KEY_MAP.get(msg.get("key"))
        if key:
            pyautogui.press(key)

    elif t == "type":
        text = str(msg.get("text", ""))[:500]
        if text:
            type_unicode(text)

    elif t == "media":
        key = MEDIA_MAP.get(msg.get("action"))
        if key:
            pyautogui.press(key)

    elif t == "system":
        action = msg.get("action")

        if action == "lock":
            ctypes.windll.user32.LockWorkStation()

        elif action in ("sleep", "shutdown", "restart"):
            power_action(action)

    elif t == "stream":
        streaming["on"] = bool(msg.get("on"))
        flow["sent"].clear()

    elif t == "frame_ack":
        if flow["sent"]:
            flow["rtt"] = (
                0.7 * flow["rtt"]
                + 0.3 * (
                    asyncio.get_event_loop().time()
                    - flow["sent"].pop(0)
                )
            )


def grab_frame(width, quality):
    """يلتقط الشاشة ويضغط الصورة."""
    img = ImageGrab.grab()
    w, h = img.size

    scale = width / w

    img = img.resize(
        (width, max(1, int(h * scale))),
        Image.BILINEAR,
    ).convert("RGB")

    draw_cursor(img, scale)

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=quality)

    return base64.b64encode(buf.getvalue()).decode("ascii")


async def frame_sender(ws):
    """إرسال إطارات الشاشة مع التحكم بسرعة وجودة البث."""
    loop = asyncio.get_running_loop()

    failing = False
    width, quality = 800, 60

    while True:
        if not streaming["on"]:
            flow["sent"].clear()
            await asyncio.sleep(0.2)
            continue

        waited = 0.0

        while (
            len(flow["sent"]) >= 2
            and waited < 2.0
            and streaming["on"]
        ):
            await asyncio.sleep(0.01)
            waited += 0.01

        if waited >= 2.0:
            flow["sent"].clear()

        t0 = loop.time()

        try:
            data = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    grab_frame,
                    width,
                    quality,
                ),
                timeout=4,
            )

            await asyncio.wait_for(
                ws.send_json({
                    "type": "frame",
                    "data": data,
                }),
                timeout=6,
            )

            flow["sent"].append(loop.time())
            failing = False

        except asyncio.TimeoutError:
            width, quality = 560, 42

        except Exception as e:
            if not failing:
                print(
                    "Screen capture paused (is the PC locked? unlock it):",
                    e,
                )

            failing = True
            await asyncio.sleep(0.5)

        took = loop.time() - t0
        rtt = flow["rtt"]

        if took > 0.35 or rtt > 0.7:
            width = max(520, width - 100)
            quality = max(38, quality - 6)

        elif took < 0.12 and rtt < 0.3 and width < 900:
            width = min(900, width + 40)
            quality = min(70, quality + 3)

        await asyncio.sleep(max(0.01, 1 / 20 - took))


def machine_id():
    """هوية ثابتة لهذا الكمبيوتر."""
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as k:
            return str(winreg.QueryValueEx(k, "MachineGuid")[0])

    except Exception:
        import uuid
        return "mac-" + str(uuid.getnode())


def load_config():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)

    except Exception:
        return {}


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f)

    except Exception as e:
        print("Could not save config:", e)


def show_pair_code(code, ttl):
    pretty = f"{code[:4]} - {code[4:]}"

    print()
    print("=" * 50)
    print(f"   PAIRING CODE:   {pretty}")
    print("=" * 50)
    print("   1) Open the website on your phone and log in")
    print('   2) Tap "Link new computer" and type this code')
    print(
        f"   (valid {ttl // 60} minutes - a new code appears automatically)"
    )
    print()


async def run(
    relay_addr: str,
    username: str,
    agent_token: str,
    password: str = "",
):
    """يرجع سببًا عند ضرورة إيقاف البرنامج."""
    scheme = (
        "wss"
        if relay_addr.startswith(("https://", "wss://"))
        else "ws"
    )

    host = (
        relay_addr.replace("https://", "")
        .replace("http://", "")
        .replace("wss://", "")
        .replace("ws://", "")
    )

    url = f"{scheme}://{host.rstrip('/')}/ws"

    hwid = machine_id()
    name = platform.node()[:60]

    print("=" * 50)
    print("  Remote Control Agent")
    print("=" * 50)
    print(f"  Server  : {host.rstrip('/')}")
    print(f"  Account : {username or '(not linked yet)'}")
    print("=" * 50)

    def hello():
        if agent_token or password:
            return {
                "type": "register_agent",
                "username": username,
                "hwid": hwid,
                "name": name,
                **(
                    {"agent_token": agent_token}
                    if agent_token
                    else {"password": password}
                ),
            }

        return {
            "type": "pair_request",
            "hwid": hwid,
            "name": name,
        }

    while True:
        sender_task = None
        refresh_task = None
        wait = 5

        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    url,
                    heartbeat=20,
                ) as ws:

                    await ws.send_json(hello())

                    async def refresh_code(ttl):
                        await asyncio.sleep(max(30, ttl - 10))
                        await ws.send_json({
                            "type": "pair_request",
                            "hwid": hwid,
                            "name": name,
                        })

                    try:
                        async for raw in ws:
                            if raw.type != aiohttp.WSMsgType.TEXT:
                                continue

                            try:
                                msg = json.loads(raw.data)

                            except json.JSONDecodeError:
                                continue

                            t = msg.get("type")

                            # ---------- Pairing code ----------
                            if t == "pair_code":
                                if msg.get("ok") is False:
                                    reason = msg.get(
                                        "reason",
                                        "unknown",
                                    )

                                    print(
                                        "Pairing request failed:",
                                        REASONS.get(reason, reason),
                                    )

                                    wait = 30
                                    break

                                code = str(msg.get("code", ""))

                                if (
                                    len(code) != 8
                                    or not code.isdigit()
                                ):
                                    print(
                                        "Invalid pairing code received."
                                    )

                                    wait = 30
                                    break

                                show_pair_code(
                                    code,
                                    int(msg.get("ttl", 600)),
                                )

                                if refresh_task:
                                    refresh_task.cancel()

                                refresh_task = asyncio.create_task(
                                    refresh_code(
                                        int(msg.get("ttl", 600))
                                    )
                                )

                                continue

                            # ---------- Pairing error ----------
                            if t == "pair_error":
                                reason = msg.get(
                                    "reason",
                                    "unknown",
                                )

                                print(
                                    "Pairing request failed:",
                                    REASONS.get(reason, reason),
                                )

                                wait = 30
                                break

                            # ---------- Pairing completed ----------
                            if t == "pair_done":
                                if refresh_task:
                                    refresh_task.cancel()

                                username = msg["username"]
                                agent_token = msg["agent_token"]

                                save_config({
                                    "relay": relay_addr,
                                    "username": username,
                                    "agent_token": agent_token,
                                })

                                print(
                                    f"Linked to account '{username}' successfully."
                                )

                                await ws.send_json(hello())
                                continue

                            # ---------- Agent registration ----------
                            if t == "registered_agent":
                                if msg.get("ok"):
                                    if msg.get("agent_token"):
                                        agent_token = msg["agent_token"]

                                        save_config({
                                            "relay": relay_addr,
                                            "username": username,
                                            "agent_token": agent_token,
                                        })

                                    print(
                                        "Connected. Open the app on your phone and tap Connect."
                                    )

                                    sender_task = asyncio.create_task(
                                        frame_sender(ws)
                                    )

                                    continue

                                reason = msg.get("reason")

                                print(
                                    "Rejected:",
                                    REASONS.get(reason, reason),
                                )

                                if reason in FATAL:
                                    return reason

                                if reason == "pending":
                                    wait = 30

                                break

                            if sender_task is None:
                                continue

                            # ---------- Controller status ----------
                            if t == "controller":
                                print(
                                    "Phone connected - remote control is ACTIVE"
                                    if msg.get("connected")
                                    else "Phone disconnected"
                                )

                            elif t == "license_ended":
                                print(
                                    "Account ended or was changed by the seller."
                                )
                                return "ended"

                            else:
                                try:
                                    handle_command(msg)

                                except Exception as e:
                                    print("Command error:", e)

                    finally:
                        streaming["on"] = False

                        if sender_task:
                            sender_task.cancel()

                        if refresh_task:
                            refresh_task.cancel()

        except Exception as e:
            print(
                "Connection lost, retrying in 5 seconds...",
                e,
            )

        await asyncio.sleep(wait)


def main():
    cfg = load_config()

    relay = (
        os.environ.get("RC_RELAY")
        or cfg.get("relay")
        or DEFAULT_RELAY
    ).strip()

    username = cfg.get("username", "").strip().lower()
    token = cfg.get("agent_token", "")

    try:
        if not relay:
            relay = input("Server address: ").strip()

        while True:
            if not token:
                username = ""

            result = asyncio.run(
                run(relay, username, token)
            )

            if result == "bad_credentials" and token:
                token = ""

                save_config({"relay": relay})

                print(
                    "This computer was unlinked. Pairing again..."
                )

                continue

            break

    except KeyboardInterrupt:
        pass

    input("\nPress Enter to close...")


if __name__ == "__main__":
    main()
