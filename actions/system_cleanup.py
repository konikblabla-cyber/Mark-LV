"""Full-disk cleanup audit for JARVIS.

Safety model:
- The scan may inspect every accessible path on every logical drive.
- It NEVER assumes that age, size or extension alone makes a file disposable.
- Only items matching a narrow, deterministic safe-delete policy can be marked
  SAFE_DELETE. Everything else is KEEP or REVIEW.
- Protected Windows/program/system locations are always KEEP.
- Deletion/uninstall remains a separate, explicit operation.
"""
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
_SCAN_LOCK = threading.Lock()
_SCAN_RUNNING = False

# Never classify anything under these locations as disposable.
_PROTECTED_DIR_NAMES = {
    "windows", "program files", "program files (x86)", "programdata",
    "recovery", "system volume information", "$recycle.bin", "boot",
    "efi", "msocache", "perflogs", "system32", "winsxs", "servicing",
}
_PROTECTED_SUFFIXES = {".sys", ".dll", ".drv", ".ocx", ".cpl", ".msi"}
# Deliberately tiny: these are strong signals, not guesses.
_SAFE_JUNK_NAMES = {"thumbs.db", "ehthumbs.db"}
_SAFE_TEMP_SUFFIXES = {".tmp", ".temp", ".crdownload", ".part"}
_CACHE_MARKERS = ("\\cache\\", "\\caches\\", "\\crashdumps\\")
_INSTALLER_SUFFIXES = {".exe", ".msi", ".msix", ".iso", ".img"}


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


def _is_protected(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if any(name in parts for name in _PROTECTED_DIR_NAMES):
        return True
    # Any file with a system/library driver extension is never disposable.
    if path.suffix.lower() in _PROTECTED_SUFFIXES:
        return True
    return False


def _classify(path: Path, now: float):
    """Return (classification, reason, confidence). Conservative by design."""
    try:
        stat = path.stat()
        age_days = (now - stat.st_mtime) / 86400
        name = path.name.lower()
        suffix = path.suffix.lower()
        normalized = str(path).lower().replace("/", "\\")
        if _is_protected(path):
            return "KEEP", "Protected Windows/system/program location or system file", "HIGH"
        if name in _SAFE_JUNK_NAMES:
            return "SAFE_DELETE", "Known disposable thumbnail database", "HIGH"
        if suffix in _SAFE_TEMP_SUFFIXES and age_days >= 30:
            # Only a temp-style extension is not enough; require a temp/cache path.
            temp_path = any(marker in normalized for marker in ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", *(_CACHE_MARKERS)))
            if temp_path:
                return "SAFE_DELETE", f"Temporary/cache artifact, {int(age_days)} days old", "HIGH"
            return "REVIEW", f"Temporary-looking extension, {int(age_days)} days old, but location is not a known temp area", "MEDIUM"
        if suffix in _INSTALLER_SUFFIXES and age_days >= 180:
            return "REVIEW", f"Old installer/image, {int(age_days)} days old — may still be needed", "LOW"
        if age_days >= 730 and stat.st_size >= 50 * 1024 * 1024:
            return "REVIEW", f"Large file, {int(age_days)} days old — age does not prove it is disposable", "LOW"
    except (OSError, PermissionError):
        return "UNKNOWN", "Could not inspect file metadata", "NONE"
    return "KEEP", "No sufficiently strong evidence that this is disposable", "HIGH"


def _progress(drive: Path, drive_files: int, total_files: int, candidates: int,
              started: float, status: str = "SCANNING"):
    elapsed = max(time.time() - started, 0.001)
    rate = total_files / elapsed
    text = (
        "JARVIS — FULL DISK SCAN\n"
        f"Status: {status}\n"
        f"Aktualny dysk: {drive}\n"
        f"Pliki na aktualnym dysku: {drive_files:,}\n"
        f"Pliki łącznie: {total_files:,}\n"
        f"Elementy wymagające uwagi: {candidates:,}\n"
        f"Prędkość: {rate:,.0f} plików/s\n"
        f"Czas: {int(elapsed // 60):02d}:{int(elapsed % 60):02d}\n"
        f"Ostatnia aktualizacja: {datetime.now().strftime('%H:%M:%S')}\n"
    )
    try:
        _REPORT_DIR.mkdir(parents=True, exist_ok=True)
        _PROGRESS_TXT.write_text(text, encoding="utf-8")
    except OSError:
        pass


def _scan(root: Path, findings: list[dict], stats: dict, started: float):
    now = time.time()
    drive_files = 0
    # Do NOT prune Windows/Program Files/etc. here. The request is a real
    # full-disk inspection. _classify() protects those locations from cleanup.
    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, onerror=lambda _e: None
    ):
        stats["directories"] += 1
        for filename in filenames:
            path = Path(dirpath) / filename
            stats["files"] += 1
            drive_files += 1
            classification, reason, confidence = _classify(path, now)
            if classification != "KEEP":
                try:
                    stat = path.stat()
                    findings.append({
                        "id": f"F{len(findings) + 1:05d}",
                        "classification": classification,
                        "confidence": confidence,
                        "path": str(path),
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="minutes"),
                        "reason": reason,
                    })
                except (OSError, PermissionError):
                    pass
            if drive_files % 500 == 0:
                _progress(root, drive_files, stats["files"], len(findings), started)
    _progress(root, drive_files, stats["files"], len(findings), started)


def _installed_apps() -> list[dict]:
    if os.name != "nt":
        return []
    ps = r'''$roots=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'); Get-ItemProperty $roots -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation,UninstallString,QuietUninstallString | ConvertTo-Json -Compress'''
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=30)
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
                "uninstall_available": bool(row.get("UninstallString") or row.get("QuietUninstallString")),
            })
        return sorted(apps, key=lambda x: x["name"].lower())
    except Exception:
        return []


def _write_report(report: dict, write_notepad: bool = True) -> Path:
    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _REPORT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    safe = [x for x in report["files"] if x["classification"] == "SAFE_DELETE"]
    review = [x for x in report["files"] if x["classification"] == "REVIEW"]
    unknown = [x for x in report["files"] if x["classification"] == "UNKNOWN"]
    lines = [
        "JARVIS — PEŁNY AUDYT WSZYSTKICH DYSKÓW",
        f"Data: {report['created_at']}",
        f"Dyski: {', '.join(report['drive_names'])}",
        f"Przeskanowane katalogi: {report['stats']['directories']:,}",
        f"Przeskanowane pliki: {report['stats']['files']:,}",
        f"Bezpieczne kandydaty: {len(safe):,}",
        f"Do ręcznego sprawdzenia: {len(review):,}",
        f"Niepewne/nieodczytane: {len(unknown):,}",
        f"Zainstalowane programy: {len(report['apps']):,}",
        "",
        "ZASADA BEZPIECZEŃSTWA:",
        "SAFE_DELETE = bardzo mocny dowód, ale nadal wymaga osobnego zatwierdzenia.",
        "REVIEW = JARVIS NIE MOŻE sam uznać tego za śmieć.",
        "KEEP = brak wystarczających dowodów na usunięcie.",
        "UNKNOWN = nie udało się sprawdzić; NIE usuwać.",
        "Żaden wiek pliku, rozmiar ani rozszerzenie nie wystarcza samo w sobie.",
        "",
        "=== DYSKI ===",
    ]
    for d in report["disks"]:
        lines.append(f"{d['drive']} | wolne: {_size(d['free'])} | zajęte: {_size(d['used'])} | razem: {_size(d['total'])}")
    for title, items in (
        ("SAFE_DELETE — NAJSILNIEJSZE KANDYDATY", safe),
        ("REVIEW — WYMAGA DECYZJI", review),
        ("UNKNOWN — NIE ODCZYTANO", unknown),
    ):
        lines += ["", f"=== {title} ===", ""]
        for item in items:
            lines += [
                f"[{item['id']}] {item['classification']} | pewność: {item['confidence']} | {_size(item['size'])}",
                f"  {item['path']}",
                f"  Zmieniono: {item['modified']}",
                f"  Powód: {item['reason']}",
                "",
            ]
    lines += ["=== ZAINSTALOWANE PROGRAMY ===", ""]
    for app in report["apps"]:
        lines.append(f"[{app['id']}] {app['name']} {app['version']} | {app['publisher']} | deinstalator: {'TAK' if app['uninstall_available'] else 'NIE'}")
        if app["install_location"]:
            lines.append(f"  {app['install_location']}")
    _REPORT_TXT.write_text("\n".join(lines), encoding="utf-8")
    if os.name == "nt" and write_notepad:
        try:
            subprocess.Popen(["notepad.exe", str(_REPORT_TXT)])
        except OSError:
            pass
    return _REPORT_TXT


def audit_computer(write_notepad: bool = True, include_apps: bool = True) -> str:
    global _SCAN_RUNNING
    with _SCAN_LOCK:
        if _SCAN_RUNNING:
            return f"FULL DISK SCAN już trwa. Postęp: {_PROGRESS_TXT}"
        _SCAN_RUNNING = True
    started = time.time()
    findings, disks = [], []
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
            _progress(drive, 0, stats["files"], len(findings), started)
            _scan(drive, findings, stats, started)
        apps = _installed_apps() if include_apps else []
        report = {
            "created_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "drive_names": [str(d) for d in drives],
            "disks": disks,
            "stats": stats,
            "files": findings,
            "apps": apps,
            "elapsed_seconds": round(time.time() - started, 1),
        }
        path = _write_report(report, write_notepad)
        _progress(drives[-1] if drives else Path.home(), 0, stats["files"], len(findings), started, "DONE")
        elapsed = report["elapsed_seconds"]
        safe_n = sum(x["classification"] == "SAFE_DELETE" for x in findings)
        review_n = sum(x["classification"] == "REVIEW" for x in findings)
        return (
            f"FULL DISK SCAN zakończony: {stats['drives']} dyski, "
            f"{stats['directories']:,} katalogów, {stats['files']:,} plików. "
            f"SAFE_DELETE: {safe_n}, REVIEW: {review_n}, "
            f"programy: {len(apps)}. Czas: {int(elapsed // 60):02d}:{int(elapsed % 60):02d}. "
            f"Raport: {path}"
        )
    finally:
        with _SCAN_LOCK:
            _SCAN_RUNNING = False


def system_cleanup(parameters: dict = None, **_ctx) -> str:
    params = parameters or {}
    action = str(params.get("action", "full_disk_scan")).strip().lower()
    if action in {"audit", "full_disk_scan", "scan_all_disks", "scan"}:
        return audit_computer(
            bool(params.get("write_notepad", True)),
            bool(params.get("include_apps", True)),
        )
    if action in {"cleanup", "uninstall"}:
        return (
            "Approval required: first review latest_cleanup.txt and explicitly "
            "approve exact SAFE_DELETE file IDs or application IDs. "
            "REVIEW/UNKNOWN items are never auto-approved."
        )
    return f"Unknown action: {action}"


TOOL = {
    "name": "system_cleanup",
    "description": (
        "TRUE FULL DISK SCAN. Inspect every accessible file on every Windows "
        "logical drive from root to bottom. Do not prune Windows/Program Files "
        "during inspection. Classify findings conservatively as SAFE_DELETE, "
        "REVIEW or UNKNOWN; protected system/program files are KEEP. "
        "Generate a detailed Notepad report and installed-app inventory. "
        "Never delete or uninstall during scanning."
    ),
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
