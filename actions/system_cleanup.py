"""Full-disk cleanup audit for JARVIS."""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

_REPORT_DIR = Path.home() / "JARVIS" / "cleanup_reports"
_REPORT_JSON = _REPORT_DIR / "latest_cleanup.json"
_REPORT_TXT = _REPORT_DIR / "latest_cleanup.txt"
_PROGRESS_TXT = _REPORT_DIR / "full_disk_scan_progress.txt"

_SKIP_DIRS = {"$recycle.bin", "system volume information", "windows", "program files", "program files (x86)", "programdata", "recovery", "appdata", "node_modules", ".git", ".venv", "venv"}
_JUNK_NAMES = {"thumbs.db", "desktop.ini", "ehthumbs.db"}
_JUNK_SUFFIXES = {".tmp", ".temp", ".dmp", ".old", ".bak", ".crdownload", ".part"}
_INSTALLER_SUFFIXES = {".exe", ".msi", ".msix", ".iso", ".img"}
_CACHE_MARKERS = ("cache", "temp", "tmp", "crashdumps", "wer")
_SCAN_LOCK = threading.Lock()
_SCAN_RUNNING = False


def _size(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def _drives() -> list[Path]:
    if os.name != "nt":
        return [Path("/")]
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    drives = []
    for i in range(26):
        if mask & (1 << i):
            root = Path(f"{chr(65 + i)}:/")
            if root.exists():
                drives.append(root)
    return drives or [Path.home()]


def _classify(path: Path, now: float):
    try:
        stat = path.stat()
        age = (now - stat.st_mtime) / 86400
        name = path.name.lower()
        suffix = path.suffix.lower()
        parent = str(path.parent).lower()
        if name in _JUNK_NAMES:
            return "system-junk", "Known harmless Windows metadata"
        if suffix in _JUNK_SUFFIXES and age >= 30:
            return "stale-temp", f"Temporary/backup file, {int(age)} days old"
        if any(x in parent for x in _CACHE_MARKERS) and age >= 30:
            return "old-cache", f"File in cache/temp area, {int(age)} days old"
        if suffix in _INSTALLER_SUFFIXES and age >= 180:
            return "old-installer", f"Installer/image, {int(age)} days old — review before removal"
        if age >= 730 and stat.st_size >= 50 * 1024 * 1024:
            return "very-old-large", f"Large file, {int(age)} days old — review manually"
    except (OSError, PermissionError):
        pass
    return None


def _progress(drive: Path, drive_files: int, total_files: int, candidates: int, started: float, status: str = "SCANNING"):
    elapsed = max(time.time() - started, 0.001)
    rate = total_files / elapsed
    text = (
        "JARVIS — FULL DISK SCAN\n"
        f"Status: {status}\n"
        f"Aktualny dysk: {drive}\n"
        f"Pliki na aktualnym dysku: {drive_files:,}\n"
        f"Pliki łącznie: {total_files:,}\n"
        f"Kandydaci: {candidates:,}\n"
        f"Prędkość: {rate:,.0f} plików/s\n"
        f"Czas: {int(elapsed // 60):02d}:{int(elapsed % 60):02d}\n"
        f"Ostatnia aktualizacja: {datetime.now().strftime('%H:%M:%S')}\n"
    )
    try:
        _REPORT_DIR.mkdir(parents=True, exist_ok=True)
        _PROGRESS_TXT.write_text(text, encoding="utf-8")
    except OSError:
        pass


def _scan(root: Path, candidates: list[dict], stats: dict, started: float):
    now = time.time()
    drive_files = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda _e: None):
        dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIRS]
        stats["directories"] += 1
        for filename in filenames:
            path = Path(dirpath) / filename
            stats["files"] += 1
            drive_files += 1
            result = _classify(path, now)
            if result:
                try:
                    stat = path.stat()
                    kind, reason = result
                    candidates.append({
                        "id": f"F{len(candidates) + 1:05d}",
                        "type": kind,
                        "path": str(path),
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="minutes"),
                        "reason": reason,
                    })
                except (OSError, PermissionError):
                    pass
            if drive_files % 500 == 0:
                _progress(root, drive_files, stats["files"], len(candidates), started)
    _progress(root, drive_files, stats["files"], len(candidates), started)


def _installed_apps() -> list[dict]:
    if os.name != "nt":
        return []
    ps = r'''$roots=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'); Get-ItemProperty $roots -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation | ConvertTo-Json -Compress'''
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=30)
        if r.returncode != 0 or not r.stdout.strip():
            return []
        data = json.loads(r.stdout)
        if isinstance(data, dict):
            data = [data]
        apps, seen = [], set()
        for row in data:
            name = str(row.get("DisplayName") or "").strip()
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            apps.append({"id": f"A{len(apps) + 1:05d}", "name": name, "version": str(row.get("DisplayVersion") or ""), "publisher": str(row.get("Publisher") or ""), "install_location": str(row.get("InstallLocation") or "")})
        return sorted(apps, key=lambda x: x["name"].lower())
    except Exception:
        return []


def _write_report(report: dict) -> Path:
    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _REPORT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [
        "JARVIS — PEŁNY AUDYT WSZYSTKICH DYSKÓW",
        f"Data: {report['created_at']}",
        f"Dyski: {', '.join(report['drive_names'])}",
        f"Przeskanowane katalogi: {report['stats']['directories']:,}",
        f"Przeskanowane pliki: {report['stats']['files']:,}",
        f"Kandydaci do sprawdzenia: {len(report['files']):,}",
        f"Zainstalowane programy: {len(report['apps']):,}",
        "",
        "WAŻNE: stary/duży plik NIE oznacza automatycznie, że jest niepotrzebny.",
        "Raport jest listą propozycji do ręcznego zatwierdzenia.",
        "",
        "=== PODSUMOWANIE DYSKÓW ===",
    ]
    for d in report["disks"]:
        lines.append(f"{d['drive']} | wolne: {_size(d['free'])} | zajęte: {_size(d['used'])} | razem: {_size(d['total'])}")
    lines += ["", "=== PLIKI DO SPRAWDZENIA ==="]
    for item in report["files"]:
        lines += [f"[{item['id']}] {item['type']} | {_size(item['size'])} | {item['modified']}", f"  {item['path']}", f"  Powód: {item['reason']}", ""]
    lines += ["=== ZAINSTALOWANE PROGRAMY ===", ""]
    for app in report["apps"]:
        lines.append(f"[{app['id']}] {app['name']} {app['version']} | {app['publisher']}")
        if app["install_location"]:
            lines.append(f"  {app['install_location']}")
    _REPORT_TXT.write_text("\n".join(lines), encoding="utf-8")
    return _REPORT_TXT


def audit_computer(write_notepad: bool = True, include_apps: bool = True) -> str:
    global _SCAN_RUNNING
    with _SCAN_LOCK:
        if _SCAN_RUNNING:
            return f"FULL DISK SCAN już trwa. Postęp: {_PROGRESS_TXT}"
        _SCAN_RUNNING = True
    started = time.time()
    candidates, disks = [], []
    stats = {"drives": 0, "directories": 0, "files": 0}
    drives = _drives()
    try:
        for drive in drives:
            stats["drives"] += 1
            try:
                du = shutil.disk_usage(drive)
                disks.append({"drive": str(drive), "total": du.total, "free": du.free, "used": du.used})
            except OSError:
                pass
            _progress(drive, 0, stats["files"], len(candidates), started)
            _scan(drive, candidates, stats, started)
        apps = _installed_apps() if include_apps else []
        report = {
            "created_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "drive_names": [str(d) for d in drives],
            "disks": disks,
            "stats": stats,
            "files": candidates,
            "apps": apps,
            "elapsed_seconds": round(time.time() - started, 1),
        }
        path = _write_report(report)
        _progress(drives[-1] if drives else Path.home(), 0, stats["files"], len(candidates), started, "DONE")
        elapsed = report["elapsed_seconds"]
        message = (f"FULL DISK SCAN zakończony: {stats['drives']} dyski, {stats['directories']:,} katalogów, "
                   f"{stats['files']:,} plików, {len(candidates):,} kandydatów, {len(apps):,} programów. "
                   f"Czas: {int(elapsed // 60):02d}:{int(elapsed % 60):02d}. Raport: {path}")
        if write_notepad and os.name == "nt":
            try:
                subprocess.Popen(["notepad.exe", str(path)])
                message += " Raport otwarty w Notatniku."
            except Exception:
                message += " Raport zapisany, ale nie udało się otworzyć Notatnika."
        return message
    finally:
        with _SCAN_LOCK:
            _SCAN_RUNNING = False


def system_cleanup(parameters: dict = None, **_ctx) -> str:
    params = parameters or {}
    action = str(params.get("action", "full_disk_scan")).strip().lower()
    if action in {"audit", "full_disk_scan", "scan_all_disks", "scan"}:
        return audit_computer(bool(params.get("write_notepad", True)), bool(params.get("include_apps", True)))
    if action in {"cleanup", "uninstall"}:
        return "Approval required: review latest_cleanup.txt and explicitly approve exact file/app IDs before deletion or uninstall."
    return f"Unknown action: {action}"


TOOL = {
    "name": "system_cleanup",
    "description": "FULL DISK SCAN: scans every accessible Windows logical drive from root to bottom, reports live progress, counts files/directories, records disk usage, finds plausible stale/junk candidates, lists installed applications, and opens a detailed Notepad report. Never deletes or uninstalls during scanning.",
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "action": {"type": "STRING", "description": "full_disk_scan | audit | scan_all_disks | cleanup | uninstall"},
            "write_notepad": {"type": "BOOLEAN", "description": "Open the completed report in Notepad on Windows"},
            "include_apps": {"type": "BOOLEAN", "description": "Include installed Windows applications"},
        },
        "required": ["action"],
    },
    "handler": system_cleanup,
}
