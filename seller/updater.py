# -*- coding: utf-8 -*-
"""Verified, logged self-updater for the Windows Remote Control Agent."""
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


def _log(message):
    try:
        path = os.path.join(tempfile.gettempdir(), "remote-control-agent-updater.log")
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(f"[{stamp}] {message}\n")
    except Exception:
        pass


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
        with _request(url, timeout=120) as response, open(destination, "wb") as out:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError("Update file exceeds size limit")
                digest.update(chunk)
                out.write(chunk)
        actual = digest.hexdigest().lower()
        if actual != str(expected_sha256).lower():
            raise RuntimeError("Update SHA-256 verification failed")
        _log(f"Downloaded and verified update ({total} bytes, SHA256 {actual}).")
        return total
    except Exception:
        try:
            os.remove(destination)
        except OSError:
            pass
        raise


def _start_replacement_helper(target, staged, version):
    log_path = os.path.join(tempfile.gettempdir(), "remote-control-agent-updater.log")
    failed_marker = target + ".update-failed"
    ps = r"""
$ErrorActionPreference = 'Stop'
$target = __TARGET__
$staged = __STAGED__
$parent = __PARENT__
$version = __VERSION__
$log = __LOG__
$failedMarker = __FAILED__
$directory = [System.IO.Path]::GetDirectoryName($target)
$name = [System.IO.Path]::GetFileName($target)
$candidate = Join-Path $directory ($name + '.update')
$backup = $target + '.previous'

function Write-Log([string]$message) {
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -LiteralPath $log -Value "[$stamp] [HELPER] $message" -Encoding UTF8
}

try {
    Write-Log "Helper started for version $version. Target: $target"
    $deadline = (Get-Date).AddSeconds(120)
    while (Get-Process -Id $parent -ErrorAction SilentlyContinue) {
        if ((Get-Date) -gt $deadline) { throw 'Parent Agent did not exit within 120 seconds.' }
        Start-Sleep -Milliseconds 300
    }

    if (-not (Test-Path -LiteralPath $staged)) { throw 'Staged update file is missing.' }
    Copy-Item -LiteralPath $staged -Destination $candidate -Force
    if (-not (Test-Path -LiteralPath $candidate)) { throw 'Candidate copy failed.' }

    $candidateHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
    $stagedHash = (Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash
    if ($candidateHash -ne $stagedHash) { throw 'Candidate SHA256 does not match staged file.' }

    if (Test-Path -LiteralPath $target) {
        Copy-Item -LiteralPath $target -Destination $backup -Force
        Write-Log "Backup created: $backup"
    }

    Move-Item -LiteralPath $candidate -Destination $target -Force
    if (-not (Test-Path -LiteralPath $target)) { throw 'New executable is missing after replacement.' }
    Write-Log 'New executable installed. Starting it now.'

    $newProcess = Start-Process -FilePath $target -WorkingDirectory $directory -PassThru
    $healthDeadline = (Get-Date).AddSeconds(25)
    do {
        Start-Sleep -Seconds 1
        $newProcess.Refresh()
        if ($newProcess.HasExited) {
            throw "Updated Agent exited during startup (exit code $($newProcess.ExitCode))."
        }
    } while ((Get-Date) -lt $healthDeadline)

    Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $failedMarker -Force -ErrorAction SilentlyContinue
    Write-Log "Version $version remained running for 25 seconds. Update succeeded."
}
catch {
    $message = $_.Exception.Message
    Write-Log "UPDATE FAILED: $message"
    try { Set-Content -LiteralPath $failedMarker -Value $version -Encoding ASCII } catch {}
    Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $backup) {
        try {
            Copy-Item -LiteralPath $backup -Destination $target -Force
            Write-Log 'Previous executable restored.'
        } catch {
            Write-Log "Rollback failed: $($_.Exception.Message)"
        }
    }

    if (Test-Path -LiteralPath $target) {
        try {
            Start-Process -FilePath $target -WorkingDirectory $directory
            Write-Log 'Restored executable launched.'
        } catch {
            Write-Log "Could not relaunch restored executable: $($_.Exception.Message)"
        }
    }
}
"""
    replacements = {
        "__TARGET__": _ps_quote(target),
        "__STAGED__": _ps_quote(staged),
        "__PARENT__": str(os.getpid()),
        "__VERSION__": _ps_quote(version),
        "__LOG__": _ps_quote(log_path),
        "__FAILED__": _ps_quote(failed_marker),
    }
    for key, value in replacements.items():
        ps = ps.replace(key, value)

    flags = (
        getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    )
    process = subprocess.Popen(
        [
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-Command", ps,
        ],
        creationflags=flags,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _log(f"Replacement helper launched (PID {process.pid}) for {version}.")


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

    target = os.path.abspath(sys.executable)
    failed_marker = target + ".update-failed"
    try:
        with open(failed_marker, "r", encoding="ascii") as stream:
            failed_version = stream.read().strip()
        if failed_version == latest:
            _log(f"Skipping version {latest}; a previous attempt failed. Install it manually or remove the marker after diagnosis.")
            return False
    except OSError:
        pass

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

    staged = os.path.join(tempfile.gettempdir(), f"remote-control-agent-{latest}.exe")
    _log(f"New release {latest} found; downloading.")
    print(f"[UPDATE] Downloading version {latest}...", flush=True)
    _download(agent_asset["browser_download_url"], staged, expected)

    try:
        _start_replacement_helper(target, staged, latest)
    except Exception:
        try:
            os.remove(staged)
        except OSError:
            pass
        raise

    print("[UPDATE] Verified update staged; restarting...", flush=True)
    _log(f"Update {latest} staged; exiting parent process for replacement.")
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
                _log(f"Update check failed: {exc}")
                print(f"[UPDATE] Check failed (will retry): {exc}", flush=True)
            time.sleep(CHECK_INTERVAL)

    threading.Thread(
        target=worker,
        name="agent-auto-updater",
        daemon=True,
    ).start()
