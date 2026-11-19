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
CHECK_INTERVAL = 15 * 60
RETRY_INTERVAL = 5 * 60
FAILED_UPDATE_COOLDOWN = 15 * 60
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
    """Launch a detached PowerShell helper that replaces and health-checks the EXE."""
    log_path = os.path.join(tempfile.gettempdir(), "remote-control-agent-updater.log")
    failed_marker = target + ".update-failed"
    helper_path = os.path.join(
        tempfile.gettempdir(),
        f"remote-control-agent-replace-{os.getpid()}-{int(time.time())}.ps1",
    )
    ps = r"""
$ErrorActionPreference = 'Stop'
$target = __TARGET__
$staged = __STAGED__
$parent = __PARENT__
$version = __VERSION__
$log = __LOG__
$failedMarker = __FAILED__
$helperPath = __HELPER__
$directory = [System.IO.Path]::GetDirectoryName($target)
$name = [System.IO.Path]::GetFileName($target)
$candidate = Join-Path $directory ($name + '.update')
$backup = $target + '.previous'
$stdoutLog = Join-Path $env:TEMP 'remote-control-agent-startup.stdout.log'
$stderrLog = Join-Path $env:TEMP 'remote-control-agent-startup.stderr.log'

function Write-Log([string]$message) {
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -LiteralPath $log -Value "[$stamp] [HELPER] $message" -Encoding UTF8
}

try {
    Write-Log "Helper started for version $version. Target: $target. Parent PID: $parent"
    $deadline = (Get-Date).AddSeconds(120)
    while (Get-Process -Id $parent -ErrorAction SilentlyContinue) {
        if ((Get-Date) -gt $deadline) { throw 'Parent Agent did not exit within 120 seconds.' }
        Start-Sleep -Milliseconds 250
    }
    Write-Log 'Parent Agent exited; replacement can begin.'

    if (-not (Test-Path -LiteralPath $staged -PathType Leaf)) { throw "Staged update is missing: $staged" }
    $stagedHash = (Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $staged -Destination $candidate -Force
    $candidateHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
    if ($candidateHash -ne $stagedHash) { throw 'Candidate SHA256 does not match staged file.' }
    Write-Log "Candidate verified ($candidateHash)."

    if (Test-Path -LiteralPath $target) {
        Copy-Item -LiteralPath $target -Destination $backup -Force
        if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { throw 'Could not create previous-version backup.' }
        Write-Log "Backup created: $backup"
    }

    Move-Item -LiteralPath $candidate -Destination $target -Force
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw 'New executable is missing after replacement.' }
    $installedHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if ($installedHash -ne $stagedHash) { throw 'Installed executable hash does not match verified download.' }
    Write-Log 'New executable installed; launching with captured startup logs.'

    Remove-Item -LiteralPath $stdoutLog,$stderrLog -Force -ErrorAction SilentlyContinue
    $newProcess = Start-Process -FilePath $target -WorkingDirectory $directory -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
    Write-Log "New Agent process started (PID $($newProcess.Id))."

    $healthDeadline = (Get-Date).AddSeconds(40)
    do {
        Start-Sleep -Seconds 1
        $newProcess.Refresh()
        if ($newProcess.HasExited) {
            $exitCode = $newProcess.ExitCode
            $stderr = ''
            if (Test-Path -LiteralPath $stderrLog) { $stderr = (Get-Content -LiteralPath $stderrLog -Raw -ErrorAction SilentlyContinue) }
            if ($stderr.Length -gt 1500) { $stderr = $stderr.Substring(0,1500) }
            throw "Updated Agent exited during startup (exit code $exitCode). $stderr"
        }
    } while ((Get-Date) -lt $healthDeadline)

    Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $failedMarker -Force -ErrorAction SilentlyContinue
    Write-Log "Version $version passed 40-second startup check. Update succeeded."
}
catch {
    $message = $_.Exception.Message
    Write-Log "UPDATE FAILED: $message"
    try { Set-Content -LiteralPath $failedMarker -Value "$version|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" -Encoding ASCII } catch {}
    Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $backup -PathType Leaf) {
        try {
            Copy-Item -LiteralPath $backup -Destination $target -Force
            Write-Log 'Previous executable restored from backup.'
        } catch {
            Write-Log "Rollback failed: $($_.Exception.Message)"
        }
    }

    if (Test-Path -LiteralPath $target -PathType Leaf) {
        try {
            Start-Process -FilePath $target -WorkingDirectory $directory
            Write-Log 'Restored executable launched.'
        } catch {
            Write-Log "Could not relaunch restored executable: $($_.Exception.Message)"
        }
    }
}
finally {
    Remove-Item -LiteralPath $helperPath -Force -ErrorAction SilentlyContinue
}
"""
    replacements = {
        "__TARGET__": _ps_quote(target),
        "__STAGED__": _ps_quote(staged),
        "__PARENT__": str(os.getpid()),
        "__VERSION__": _ps_quote(version),
        "__LOG__": _ps_quote(log_path),
        "__FAILED__": _ps_quote(failed_marker),
        "__HELPER__": _ps_quote(helper_path),
    }
    for key, value in replacements.items():
        ps = ps.replace(key, value)

    # Use a standalone script to avoid command-line length and quoting issues.
    with open(helper_path, "w", encoding="utf-8-sig", newline="\r\n") as stream:
        stream.write(ps)

    flags = (
        getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    )
    try:
        process = subprocess.Popen(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", helper_path,
            ],
            creationflags=flags,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _log(f"Detached replacement helper launched (PID {process.pid}) for {version}; script: {helper_path}.")
    except Exception:
        try:
            os.remove(helper_path)
        except OSError:
            pass
        raise

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
            marker = stream.read().strip().split("|", 1)
        failed_version = marker[0]
        failed_at = int(marker[1]) if len(marker) == 2 else 0
        if failed_version == latest and failed_at and (time.time() - failed_at) < FAILED_UPDATE_COOLDOWN:
            remaining = int(FAILED_UPDATE_COOLDOWN - (time.time() - failed_at))
            _log(f"Previous update attempt for {latest} failed; retrying automatically in about {remaining}s.")
            return False
        if failed_version == latest:
            _log(f"Retry cooldown expired for {latest}; trying the update again.")
    except (OSError, ValueError):
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
                print(f"[UPDATE] Check failed (will retry in {RETRY_INTERVAL}s): {exc}", flush=True)
                time.sleep(RETRY_INTERVAL)
            else:
                time.sleep(CHECK_INTERVAL)

    threading.Thread(
        target=worker,
        name="agent-auto-updater",
        daemon=True,
    ).start()
