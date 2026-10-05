"""Whole-computer cleanup audit.

This module is deliberately audit-first: it scans accessible local drives,
finds plausible cleanup candidates, lists installed Windows applications, and
writes a human-readable report. It never deletes files or uninstalls software
as part of the audit.
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

_REPORT_DIR = Path.home() / "JARVIS" / "cleanup_reports"
_REPORT_JSON = _REPORT_DIR / "latest_cleanup.json"
_REPORT_TXT = _REPORT_DIR / "latest_cleanup.txt"

_SKIP_DIRS = {
    "$recycle.bin", "system volume information", "windows",
    "program files", "program files (x86)", "programdata", "recovery",
    "appdata", "node_modules", ".git", ".venv", "venv"
}
_JUNK_NAMES = {"thumbs.db", "desktop.ini", "ehthumbs.db"}
_JUNK_SUFFIXES = {".tmp", ".temp", ".dmp", ".old", ".bak", ".crdownload", ".part"}
_INSTALLER_SUFFIXES = {".exe", ".msi", ".msix", ".iso", ".img"}
_CACHE_MARKERS = ("cache", "temp", "tmp", "crashdumps", "wer")


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
    result = []
    for i in range(26):
        if mask & (1 << i):
            root = Path(f"{chr(65 + i)}:/")
            if root.exists():
                result.append(root)
    return result or [Path.home()]


def _skip_dir(path: Path) -> bool:
    return path.name.lower() in _SKIP_DIRS


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


def _scan(root: Path, candidates: list[dict], stats: dict):
    now = time.time()
    try:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda _e: None):
            dirnames[:] = [d for d in dirnames if not _skip_dir(Path(dirpath) / d)]
            stats["directories"] += 1
            for filename in filenames:
                path = Path(dirpath) / filename
                stats["files"] += 1
                result = _classify(path, now)
                if not result:
                    continue
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
                    continue
    except (OSError, PermissionError):
        pass


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
            apps.append({
                "id": f"A{len(apps) + 1:05d}",
                "name": name,
                "version": str(row.get("DisplayVersion") or ""),
                "publisher": str(row.get("Publisher") or ""),
                "install_location": str(row.get("InstallLocation") or ""),
            })
        return sorted(apps, key=lambda x: x["name"].lower())
    except Exception:
        return []


def _write_report(report: dict) -> Path:
    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _REPORT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [
        "JARVIS — AUDYT CZYSZCZENIA KOMPUTERA",
        f"Data: {report['created_at']}",
        f"Dyski: {report['stats']['drives']}",
        f"Przeskanowane pliki: {report['stats']['files']}",
        f"Kandydaci do sprawdzenia: {len(report['files'])}",
        "",
        "WAŻNE: stary plik nie oznacza automatycznie, że jest niepotrzebny.",
        "Lista jest propozycją do ręcznego zatwierdzenia.",
        "",
        "=== PLIKI ===",
    ]
    for item in report["files"]:
        lines += [
            f"[{item['id']}] {item['type']} | {_size(item['size'])} | {item['modified']}",
            f"  {item['path']}",
            f"  Powód: {item['reason']}",
            "",
        ]
    lines += ["=== ZAINSTALOWANE PROGRAMY ===", ""]
    for app in report["apps"]:
        lines.append(f"[{app['id']}] {app['name']} {app['version']} | {app['publisher']}")
        if app["install_location"]:
            lines.append(f"  {app['install_location']}")
    _REPORT_TXT.write_text("\n".join(lines), encoding="utf-8")
    return _REPORT_TXT


def audit_computer(write_notepad: bool = True, include_apps: bool = True) -> str:
    candidates = []
    stats = {"drives": 0, "directories": 0, "files": 0}
    for drive in _drives():
        stats["drives"] += 1
        _scan(drive, candidates, stats)
    apps = _installed_apps() if include_apps else []
    report = {
        "created_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "stats": stats,
        "files": candidates,
        "apps": apps,
    }
    path = _write_report(report)
    message = f"Audyt gotowy: {stats['drives']} dyski, {stats['files']} plików, {len(candidates)} kandydatów, {len(apps)} programów. Raport: {path}"
    if write_notepad and os.name == "nt":
        try:
            subprocess.Popen(["notepad.exe", str(path)])
            message += " Raport otwarty w Notatniku."
        except Exception:
            message += " Raport zapisany, ale nie udało się otworzyć Notatnika."
    return message


def system_cleanup(parameters: dict = None, **_ctx) -> str:
    params = parameters or {}
    action = str(params.get("action", "audit")).strip().lower()
    if action == "audit":
        return audit_computer(
            write_notepad=bool(params.get("write_notepad", True)),
            include_apps=bool(params.get("include_apps", True)),
        )
    if action in {"cleanup", "uninstall"}:
        return "This action is intentionally approval-gated. First review latest_cleanup.txt and explicitly approve the exact file/app IDs; the audit itself never deletes or uninstalls anything."
    return f"Unknown action: {action}"


TOOL = {
    "name": "system_cleanup",
    "description": "Scans the entire accessible computer, finds plausible junk/stale files, lists installed Windows applications, and writes a detailed Notepad report. The audit never deletes or uninstalls anything.",
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "action": {"type": "STRING", "description": "audit | cleanup | uninstall"},
            "write_notepad": {"type": "BOOLEAN", "description": "Open the report in Notepad on Windows"},
            "include_apps": {"type": "BOOLEAN", "description": "Include installed Windows applications"},
        },
        "required": ["action"],
    },
    "handler": system_cleanup,
}
