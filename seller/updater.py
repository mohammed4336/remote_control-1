# -*- coding: utf-8 -*-
"""Verified self-updater for the Windows Remote Control Agent."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

OWNER = "mohammed4336"
REPO = "remote_control-1"
API_LATEST = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
CHECK_INTERVAL = 6 * 60 * 60
MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024


def _request(url, timeout=30):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Remote-Control-Agent-Updater",
            "Accept": "application/vnd.github+json",
        },
    )
    return urllib.request.urlopen(req, timeout=timeout)


def _version_tuple(value):
    parts = []
    for item in str(value or "").strip().lstrip("vV").split("."):
        digits = "".join(ch for ch in item if ch.isdigit())
        if not digits:
            return ()
        parts.append(int(digits))
    return tuple(parts)


def _ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def _download(url, destination, expected_sha256):
    digest = hashlib.sha256()
    total = 0
    try:
        with _request(url, timeout=90) as response, open(destination, "wb") as out:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError("Update file exceeds size limit")
                digest.update(chunk)
                out.write(chunk)
        if digest.hexdigest().lower() != str(expected_sha256).lower():
            raise RuntimeError("Update SHA-256 verification failed")
        return total
    except Exception:
        try:
            os.remove(destination)
        except OSError:
            pass
        raise


def _start_replacement_helper(target, staged):
    # Copy to a temporary file beside the installed EXE so the final rename
    # stays on the same volume. Keep one previous EXE as a recovery copy.
    ps = r"""
$ErrorActionPreference = 'Stop'
$target = __TARGET__
$staged = __STAGED__
$parent = __PARENT__
$directory = [System.IO.Path]::GetDirectoryName($target)
$name = [System.IO.Path]::GetFileName($target)
$candidate = Join-Path $directory ($name + '.update')
$backup = $target + '.previous'

while (Get-Process -Id $parent -ErrorAction SilentlyContinue) {
    Start-Sleep -Milliseconds 300
}

try {
    Copy-Item -LiteralPath $staged -Destination $candidate -Force
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw 'Staged update could not be copied beside the Agent.'
    }

    # Preserve the currently working executable before replacing it.
    Copy-Item -LiteralPath $target -Destination $backup -Force
    Move-Item -LiteralPath $candidate -Destination $target -Force

    if (-not (Test-Path -LiteralPath $target)) {
        throw 'New executable is missing after replacement.'
    }

    $newProcess = Start-Process -FilePath $target -PassThru
    Start-Sleep -Seconds 4
    $newProcess.Refresh()

    if ($newProcess.HasExited) {
        throw 'Updated Agent exited immediately; rolling back.'
    }

    Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    # Keep .previous until the next successful update. It is the recovery copy.
}
catch {
    Write-Output ('Update failed: ' + $_.Exception.Message)
    Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $backup) {
        try {
            Copy-Item -LiteralPath $backup -Destination $target -Force
        } catch {
            Write-Output ('Rollback copy failed: ' + $_.Exception.Message)
        }
    }

    if (Test-Path -LiteralPath $target) {
        Start-Process -FilePath $target
    }
}
""".replace("__TARGET__", _ps_quote(target))
    ps = ps.replace("__STAGED__", _ps_quote(staged))
    ps = ps.replace("__PARENT__", str(os.getpid()))

    flags = (
        getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    )
    subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps,
        ],
        creationflags=flags,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def check_and_stage(current_version):
    if not getattr(sys, "frozen", False) or os.name != "nt":
        return False

    with _request(API_LATEST) as response:
        release = json.loads(response.read().decode("utf-8"))

    if release.get("draft") or release.get("prerelease"):
        return False

    latest = str(release.get("tag_name", "")).lstrip("vV")
    current = _version_tuple(current_version)
    remote = _version_tuple(latest)
    if not current or not remote or remote <= current:
        return False

    assets = {
        asset.get("name"): asset
        for asset in release.get("assets", [])
        if asset.get("name")
    }
    metadata_asset = assets.get("update.json")
    agent_asset = assets.get("agent.exe")
    if not metadata_asset or not agent_asset:
        raise RuntimeError("Release must contain agent.exe and update.json")

    with _request(metadata_asset["browser_download_url"]) as response:
        metadata = json.loads(response.read().decode("utf-8-sig"))

    if str(metadata.get("version", "")).lstrip("vV") != latest:
        raise RuntimeError("Release metadata version does not match its tag")

    expected = str(metadata.get("sha256", "")).lower()
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise RuntimeError("Release metadata has an invalid SHA-256")

    target = os.path.abspath(sys.executable)
    staged = os.path.join(
        tempfile.gettempdir(),
        f"remote-control-agent-{latest}.exe",
    )

    print(f"[UPDATE] Downloading version {latest}...", flush=True)
    _download(agent_asset["browser_download_url"], staged, expected)

    try:
        _start_replacement_helper(target, staged)
    except Exception:
        try:
            os.remove(staged)
        except OSError:
            pass
        raise

    print("[UPDATE] Verified update staged; restarting...", flush=True)
    return True


def start_auto_updater(current_version):
    if not getattr(sys, "frozen", False) or os.name != "nt":
        return

    def worker():
        while True:
            try:
                if check_and_stage(current_version):
                    os._exit(0)
            except Exception as exc:
                print(f"[UPDATE] Check failed (will retry): {exc}", flush=True)
            time.sleep(CHECK_INTERVAL)

    threading.Thread(
        target=worker,
        name="agent-auto-updater",
        daemon=True,
    ).start()
