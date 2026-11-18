# -*- coding: utf-8 -*-
"""Optional LAN Wake-on-LAN bridge for Remote Control."""
import asyncio, getpass, ipaddress, re, socket
import aiohttp

DEFAULT_RELAY = "https://remote-control-by-akira.onrender.com"
MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

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
    print("=" * 54)
    print("Remote Control - Wake Bridge")
    print("Keep this device powered on and connected to the same LAN.")
    print("=" * 54)
    relay = input("Relay URL [default]: ").strip() or DEFAULT_RELAY
    username = input("Account username: ").strip().lower()
    password = getpass.getpass("Account password: ")
    if not username or not password:
        raise SystemExit("Username and password are required.")
    if relay.startswith("https://"): url = "wss://" + relay[8:].rstrip("/") + "/ws"
    elif relay.startswith("http://"): url = "ws://" + relay[7:].rstrip("/") + "/ws"
    else: raise SystemExit("Relay URL must use https:// or http://")
    delay = 3
    while True:
        try:
            timeout = aiohttp.ClientTimeout(total=None, sock_connect=15, sock_read=None)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(url, heartbeat=20, max_msg_size=1024*1024) as ws:
                    await ws.send_json({"type":"register_wake_bridge","username":username,"password":password})
                    first = await ws.receive(timeout=20)
                    if first.type != aiohttp.WSMsgType.TEXT: raise RuntimeError("No registration response")
                    reply = __import__("json").loads(first.data)
                    if reply.get("type") != "wake_bridge_registered" or not reply.get("ok"):
                        raise RuntimeError("Registration failed: "+str(reply.get("reason","unknown")))
                    print("[OK] Secure connection established. Waiting for wake requests...")
                    delay = 3
                    async for raw in ws:
                        if raw.type != aiohttp.WSMsgType.TEXT: continue
                        try: msg = __import__("json").loads(raw.data)
                        except Exception: continue
                        if msg.get("type") != "wake_pc": continue
                        try:
                            send_magic_packet(str(msg.get("mac","")),str(msg.get("broadcast","255.255.255.255")))
                            await ws.send_json({"type":"wake_result","ok":True})
                        except Exception as exc:
                            await ws.send_json({"type":"wake_result","ok":False,"reason":str(exc)[:80]})
        except KeyboardInterrupt: break
        except Exception as exc:
            print("[Bridge] Connection error:",str(exc)[:180])
            print("[Bridge] Reconnecting in",delay,"seconds...")
            await asyncio.sleep(delay)
            delay=min(delay*2,60)

if __name__ == "__main__":
    try: asyncio.run(run())
    except KeyboardInterrupt: print("\nWake Bridge stopped.")
