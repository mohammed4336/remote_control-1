# -*- coding: utf-8 -*-
"""Low-latency WebRTC desktop video track for the Windows agent.

DXcam is preferred for Windows desktop capture. Pillow ImageGrab is retained
as a compatibility fallback. Frames are sent as a real-time video track rather
than JPEG/Base64 messages through the relay.
"""
import asyncio
import logging
import time

import numpy as np
from aiortc import RTCPeerConnection, RTCSessionDescription, VideoStreamTrack
from aiortc.contrib.media import MediaRelay
from av import VideoFrame

log = logging.getLogger("remote-control.webrtc")


class DesktopVideoTrack(VideoStreamTrack):
    def __init__(self, monitor_index=0, fps=30, width=1280, monitor_rect=None):
        super().__init__()
        self.monitor_index = max(0, int(monitor_index))
        self.fps = max(5, min(60, int(fps)))
        self.width = max(640, min(1920, int(width)))
        self.monitor_rect = monitor_rect
        self.camera = None
        self._dxcam = False
        self._last_frame = None
        self._last_capture = 0.0

    def _start_camera(self):
        try:
            import dxcam
            self.camera = dxcam.create(
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
        self._last_frame = frame
        return frame

    async def recv(self):
        pts, time_base = await self.next_timestamp()
        # DXcam runs its own capture thread; only the newest frame is read.
        frame = await asyncio.to_thread(self._capture)
        video = VideoFrame.from_ndarray(frame, format="rgb24")
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


async def answer_offer(sdp, sdp_type, monitor_index=0, fps=30, width=1280, monitor_rect=None):
    """Create an aiortc peer and return (peer, track, answer SDP)."""
    pc = RTCPeerConnection()
    track = DesktopVideoTrack(
        monitor_index=monitor_index,
        fps=fps,
        width=width,
        monitor_rect=monitor_rect,
    )
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
