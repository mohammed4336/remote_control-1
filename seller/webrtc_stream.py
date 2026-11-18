# -*- coding: utf-8 -*-
"""Low-latency WebRTC desktop video track for the Windows agent.

DXcam is preferred for Windows desktop capture. Pillow ImageGrab is retained
as a compatibility fallback. Frames are sent as a real-time video track rather
than JPEG/Base64 messages through the relay.
"""
import asyncio
import ctypes
from ctypes import wintypes
import logging
import time
from fractions import Fraction

import numpy as np
from aiortc import RTCPeerConnection, RTCConfiguration, RTCIceServer, RTCSessionDescription, VideoStreamTrack
import os
from av import VideoFrame

log = logging.getLogger("remote-control.webrtc")

# Import DXcam before legacy desktop-control/audio libraries initialize COM.
try:
    import dxcam as _dxcam
except Exception as _dxcam_import_error:
    _dxcam = None
    log.warning("DXcam import unavailable; ImageGrab fallback will be used: %s", _dxcam_import_error)


class DesktopVideoTrack(VideoStreamTrack):
    def __init__(self, monitor_index=0, fps=30, width=1280, monitor_rect=None):
        super().__init__()
        self.monitor_index = max(0, int(monitor_index))
        self.fps = max(5, min(60, int(fps)))
        self.width = max(640, min(1920, int(width)))
        self.monitor_rect = monitor_rect
        self.camera = None
        self._dxcam = False
        self._last_capture = 0.0
        self._video_pts = 0
        self._video_started = None

    def _start_camera(self):
        try:
            if _dxcam is None:
                raise RuntimeError("DXcam is not available")
            self.camera = _dxcam.create(
                output_idx=self.monitor_index,
                output_color="RGB",
            )
            self.camera.start(target_fps=self.fps, video_mode=True)
            self._dxcam = True
            log.info("DXcam capture started: monitor=%s fps=%s", self.monitor_index, self.fps)
        except Exception as exc:
            self.camera = None
            self._dxcam = False
            log.warning("DXcam unavailable; using ImageGrab fallback: %s", exc)

    def _capture(self):
        if self.camera is None and self._last_capture == 0.0:
            self._start_camera()

        frame = None
        if self.camera is not None:
            try:
                frame = self.camera.get_latest_frame()
            except Exception as exc:
                log.warning("DXcam frame failed, switching to ImageGrab: %s", exc)
                try:
                    self.camera.stop()
                except Exception:
                    pass
                self.camera = None
                self._dxcam = False

        if frame is None:
            from PIL import ImageGrab
            if self.monitor_rect:
                left, top, right, bottom = self.monitor_rect
                image = ImageGrab.grab(bbox=(left, top, right, bottom), all_screens=True)
            else:
                image = ImageGrab.grab(all_screens=True)
            image = image.convert("RGB")
            target_h = max(1, int(image.height * self.width / image.width))
            image = image.resize((self.width, target_h))
            frame = np.asarray(image, dtype=np.uint8)
        else:
            frame = np.asarray(frame)
            if frame.ndim == 3 and frame.shape[2] == 4:
                frame = frame[:, :, :3]
            if frame.shape[1] > self.width:
                target_h = max(1, int(frame.shape[0] * self.width / frame.shape[1]))
                from PIL import Image
                frame = np.asarray(
                    Image.fromarray(frame).resize((self.width, target_h)),
                    dtype=np.uint8,
                )
        self._last_capture = time.monotonic()
        return np.ascontiguousarray(frame, dtype=np.uint8)

    def _draw_cursor(self, frame):
        if not self.monitor_rect:
            return frame
        try:
            point = wintypes.POINT()
            ctypes.windll.user32.GetCursorPos(ctypes.byref(point))
            left, top, right, bottom = self.monitor_rect
            x = point.x - left
            y = point.y - top
            if not (0 <= x < right - left and 0 <= y < bottom - top):
                return frame
            scale = frame.shape[1] / max(1, right - left)
            x, y = int(x * scale), int(y * scale)
            from PIL import Image, ImageDraw
            image = Image.fromarray(frame)
            draw = ImageDraw.Draw(image)
            points = [(x, y), (x, y + 16), (x + 4, y + 12),
                      (x + 8, y + 20), (x + 11, y + 18),
                      (x + 7, y + 11), (x + 13, y + 11)]
            draw.polygon(points, fill="white", outline="black")
            return np.asarray(image, dtype=np.uint8)
        except Exception:
            return frame

    async def recv(self):
        # aiortc's base VideoStreamTrack is fixed at 30 FPS. Use a 90 kHz
        # media clock so the selected 30/60 FPS target is honored.
        interval = 90000 // self.fps
        if self._video_started is None:
            self._video_started = time.monotonic()
        else:
            self._video_pts += interval
            deadline = self._video_started + (self._video_pts / 90000)
            delay = deadline - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)

        pts = self._video_pts
        time_base = Fraction(1, 90000)
        # DXcam runs its own capture thread; only the newest frame is read.
        frame = await asyncio.to_thread(self._capture)
        frame = self._draw_cursor(frame)
        video = VideoFrame.from_ndarray(np.ascontiguousarray(frame), format="rgb24")
        video.pts = pts
        video.time_base = time_base
        return video

    def stop(self):
        try:
            if self.camera is not None:
                self.camera.stop()
        except Exception:
            pass
        self.camera = None
        super().stop()


async def answer_offer(sdp, sdp_type, monitor_index=0, fps=30, width=1280, monitor_rect=None, ice_servers=None):
    """Create an aiortc peer and return (peer, track, answer SDP)."""
    configured = []
    for item in (ice_servers or []):
        if not isinstance(item, dict) or not item.get("urls"):
            continue
        kwargs = {"urls": item["urls"]}
        if item.get("username"):
            kwargs["username"] = item["username"]
        if item.get("credential"):
            kwargs["credential"] = item["credential"]
        configured.append(RTCIceServer(**kwargs))
    if not configured:
        configured = [RTCIceServer(urls=["stun:stun.l.google.com:19302"])]

    pc = RTCPeerConnection(RTCConfiguration(iceServers=configured))
    track = DesktopVideoTrack(
        monitor_index=monitor_index,
        fps=fps,
        width=width,
        monitor_rect=monitor_rect,
    )
    # Create the DXGI capture device on the agent's main thread; DXcam owns
    # its capture thread and exposes only the newest frame to the encoder.
    track._start_camera()
    pc.addTrack(track)
    await pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type=sdp_type))
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    # aiortc gathers ICE candidates as part of setLocalDescription.
    local = pc.localDescription
    return pc, track, {"type": local.type, "sdp": local.sdp}


async def close_peer(pc, track=None):
    if track is not None:
        try:
            track.stop()
        except Exception:
            pass
    if pc is not None:
        try:
            await pc.close()
        except Exception:
            pass
