#!/usr/bin/env python3
"""
Local Network Media Server & Windows Drive Explorer (FastAPI + Uvicorn)
=======================================================================
UI/UX: Minimalist Editorial Design System (Swiss-style / Linear inspired)
Architecture:
- Storage Hub View (when at root '/'): Drive cards with live capacity bars, quick shortcuts, jump input.
- File Explorer View (when path is selected): Breadcrumbs, parent navigation, folders grid, media files list/grid.
- Theater Mode Lightbox: Real-time video player with HTTP 206 partial-content seeking, audio, image viewer.
- Full Security Suite: httpOnly cookies, server-side auth, 2FA Security PIN, 15-min IP rate limiting, password auditing.
"""

import datetime
import hashlib
import hmac
import html
import mimetypes
import os
import secrets
import shutil
import socket
import string
import sys
import time
from email.utils import formatdate
from pathlib import Path
from typing import Iterator, List, Optional, Tuple
from urllib.parse import quote

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION (.env supported)
# ──────────────────────────────────────────────────────────────────────────────
def _load_env_file():
    for base in [Path(__file__).resolve().parent, Path(__file__).resolve().parent.parent]:
        env_file = base / ".env"
        if env_file.exists():
            try:
                for line in env_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip().strip("'\"")
                    if k not in os.environ:
                        os.environ[k] = v
            except Exception:
                pass
            break

_load_env_file()

USERNAME = os.getenv("MEDIA_USER", "daredevil717")
PASSWORD = os.getenv("MEDIA_PASS", "hellskitchen")
MEDIA_PIN = os.getenv("MEDIA_PIN", "717007")  # 2FA 6-digit Security PIN
HOST = os.getenv("MEDIA_HOST", "0.0.0.0")
PORT = int(os.getenv("MEDIA_PORT", "8000"))
CHUNK_SIZE = 1024 * 1024  # 1 MB
SESSION_MAX_AGE = 86400   # 24 hours

# Optional default folder path (from .env or CLI arg)
DEFAULT_PATH: Optional[str] = os.getenv("DEFAULT_PATH") or None

REALM = "Local Media Server"
SESSION_SECRET = secrets.token_hex(32)

# Ensure common media types resolve consistently
for _ext, _mime in {
    ".mp4": "video/mp4",
    ".m4v": "video/mp4",
    ".mov": "video/quicktime",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
    ".avi": "video/x-msvideo",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".wav": "audio/wav",
    ".flac": "audio/flac",
    ".aac": "audio/aac",
    ".webp": "image/webp",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".heic": "image/heic",
    ".avif": "image/avif",
    ".pdf": "application/pdf",
}.items():
    mimetypes.add_type(_mime, _ext)

# ──────────────────────────────────────────────────────────────────────────────
# SECURITY: RATE LIMITING & LOCKOUT (Anti-Brute Force)
# ──────────────────────────────────────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME_SECONDS = 900       # 15 minutes
ATTEMPT_WINDOW_SECONDS = 900     # 15 minutes window
_FAILED_LOGINS = {}


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "127.0.0.1"


def check_login_rate_limit(client_ip: str) -> Optional[int]:
    now = time.time()
    record = _FAILED_LOGINS.get(client_ip)
    if not record:
        return None
    locked_until = record.get("locked_until", 0)
    if locked_until > now:
        return int(locked_until - now)
    if now - record.get("last_attempt", 0) > ATTEMPT_WINDOW_SECONDS:
        _FAILED_LOGINS.pop(client_ip, None)
    return None


def record_failed_login(client_ip: str) -> Tuple[int, int]:
    now = time.time()
    record = _FAILED_LOGINS.setdefault(client_ip, {"attempts": 0, "locked_until": 0, "last_attempt": now})
    if now - record.get("last_attempt", 0) > ATTEMPT_WINDOW_SECONDS and record.get("locked_until", 0) <= now:
        record["attempts"] = 0
    record["attempts"] += 1
    record["last_attempt"] = now
    if record["attempts"] >= MAX_LOGIN_ATTEMPTS:
        record["locked_until"] = now + LOCKOUT_TIME_SECONDS
        return record["attempts"], LOCKOUT_TIME_SECONDS
    return record["attempts"], 0


def clear_failed_logins(client_ip: str):
    _FAILED_LOGINS.pop(client_ip, None)


# ──────────────────────────────────────────────────────────────────────────────
# SECURITY: PASSWORD AUDITING & BREACH BLACKLIST
# ──────────────────────────────────────────────────────────────────────────────
COMMON_BREACHED_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "admin", "admin123", "welcome", "login", "guest",
    "pass1234", "master", "iloveyou", "password123", "letmein", "sunshine",
    "princess", "football", "666666", "123123", "testing", "root", "toor",
}


def audit_password_strength(password: str) -> List[str]:
    warnings = []
    if len(password) < 10:
        warnings.append(f"Password is too short ({len(password)} chars). Minimum 10 characters recommended.")
    if password.lower() in COMMON_BREACHED_PASSWORDS:
        warnings.append("Password matches a known-breached/dictionary password.")
    return warnings


# ──────────────────────────────────────────────────────────────────────────────
# SECURITY: SERVER-SIDE AUTH, TIMESTAMPED HMAC TOKENS, 2FA PIN
# ──────────────────────────────────────────────────────────────────────────────
def create_session_token(username: str) -> str:
    ts = str(int(time.time()))
    payload = f"{ts}:{username}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_token(token: Optional[str]) -> bool:
    if not token or ":" not in token:
        return False
    parts = token.split(":")
    if len(parts) != 3:
        return False
    ts_str, user, sig = parts
    try:
        ts = int(ts_str)
    except ValueError:
        return False

    now = time.time()
    if now - ts > SESSION_MAX_AGE or ts > now + 60:
        return False

    payload = f"{ts_str}:{user}"
    expected_sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not secrets.compare_digest(sig, expected_sig):
        return False

    return secrets.compare_digest(user, USERNAME)


class _AuthRequired(Exception):
    pass


def require_login(request: Request) -> str:
    token = request.cookies.get("session") or request.query_params.get("token")
    if not verify_session_token(token):
        raise _AuthRequired()
    return USERNAME


class _LoginData(BaseModel):
    username: str
    password: str
    pin: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI APP
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=REALM,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def render_template(template_name: str, **context) -> str:
    template_path = TEMPLATES_DIR / template_name
    content = template_path.read_text(encoding="utf-8")
    for key, val in context.items():
        content = content.replace(f"{{{{{key}}}}}", str(val))
    return content


@app.exception_handler(_AuthRequired)
async def _auth_redirect(request: Request, exc: _AuthRequired):
    return RedirectResponse(url="/login", status_code=303)


# ──────────────────────────────────────────────────────────────────────────────
# SYSTEM & PATH HELPERS
# ──────────────────────────────────────────────────────────────────────────────
SYSTEM_IGNORE_NAMES = {
    "$recycle.bin",
    "system volume information",
    "recovery",
    "msocache",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "dumpstack.log.tmp",
    "__pycache__",
    ".git",
    ".idea",
    ".vscode",
}

_SKIP_EXTENSIONS = {".py", ".pyc", ".pyo"}


def is_hidden_or_system(name: str) -> bool:
    low = name.lower()
    if low.startswith(".") or low.startswith("$"):
        return True
    return low in SYSTEM_IGNORE_NAMES


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} B"


def format_mtime(mtime: float) -> str:
    dt = datetime.datetime.fromtimestamp(mtime)
    now = datetime.datetime.now()
    if dt.date() == now.date():
        return f"Today, {dt.strftime('%H:%M')}"
    elif dt.date() == (now - datetime.timedelta(days=1)).date():
        return f"Yesterday, {dt.strftime('%H:%M')}"
    elif dt.year == now.year:
        return dt.strftime("%b %d, %H:%M")
    else:
        return dt.strftime("%b %d, %Y")


def guess_mime(path: Path) -> str:
    mime, _ = mimetypes.guess_type(path.name)
    return mime or "application/octet-stream"


def get_available_drives() -> List[dict]:
    drives = []
    tones = ["", "mid", "light"]
    for i, letter in enumerate(string.ascii_uppercase):
        drive_path = f"{letter}:\\"
        if os.path.exists(drive_path):
            info = {
                "letter": letter,
                "path": drive_path,
                "name": f"Local Disk ({letter}:)",
                "total": 0,
                "free": 0,
                "used": 0,
                "percent": 0,
                "tone": tones[i % len(tones)],
            }
            try:
                usage = shutil.disk_usage(drive_path)
                info["total"] = usage.total
                info["free"] = usage.free
                info["used"] = usage.used
                if usage.total > 0:
                    info["percent"] = round((usage.used / usage.total) * 100)
            except (PermissionError, OSError):
                pass
            drives.append(info)
    return drives


def count_folder_items(folder_path: Path) -> str:
    try:
        count = sum(1 for entry in os.scandir(folder_path) if not is_hidden_or_system(entry.name))
        return f"{count} items" if count != 1 else "1 item"
    except (PermissionError, OSError):
        return "Protected"


def get_quick_shortcuts() -> List[dict]:
    shortcuts = []
    server_dir = Path(__file__).resolve().parent
    shortcuts.append({
        "name": "Test_2 Folder",
        "path": str(server_dir),
        "count": count_folder_items(server_dir),
    })

    parent_dir = server_dir.parent
    if parent_dir.exists():
        shortcuts.append({
            "name": "MediaServer Root",
            "path": str(parent_dir),
            "count": count_folder_items(parent_dir),
        })

    home = Path.home()
    if home.exists():
        for sub_name in ("Videos", "Downloads", "Pictures"):
            sub_path = home / sub_name
            if sub_path.exists():
                shortcuts.append({
                    "name": sub_name,
                    "path": str(sub_path),
                    "count": count_folder_items(sub_path),
                })
        shortcuts.append({
            "name": "User Profile",
            "path": str(home),
            "count": count_folder_items(home),
        })

    return shortcuts


def normalize_target_path(path_str: Optional[str]) -> Path:
    if not path_str or not path_str.strip():
        if DEFAULT_PATH:
            return Path(DEFAULT_PATH).resolve()
        return Path(__file__).resolve().parent

    raw = path_str.strip()
    if len(raw) == 2 and raw[1] == ":" and raw[0].isalpha():
        raw = f"{raw}\\"
    elif len(raw) == 3 and raw[1] == ":" and raw[2] in ("/\\"):
        raw = f"{raw[0]}:\\"

    try:
        target = Path(raw).resolve()
        if target.exists() and target.is_dir():
            return target
    except Exception:
        pass

    return Path(__file__).resolve().parent


def build_breadcrumbs(target_path: Path) -> List[Tuple[str, str]]:
    crumbs = []
    target = target_path.resolve()
    drive = target.drive
    if drive:
        drive_root = f"{drive}\\"
        crumbs.append((f"{drive}\\", drive_root))
        try:
            rel = target.relative_to(drive_root)
            accumulated = Path(drive_root)
            for part in rel.parts:
                accumulated = accumulated / part
                crumbs.append((part, str(accumulated)))
        except ValueError:
            crumbs = [(str(target), str(target))]
    else:
        parts = target.parts
        if parts:
            accumulated = Path(parts[0])
            crumbs.append((str(parts[0]), str(accumulated)))
            for part in parts[1:]:
                accumulated = accumulated / part
                crumbs.append((part, str(accumulated)))
    return crumbs


def get_parent_path(target_path: Path) -> Optional[str]:
    target = target_path.resolve()
    if target.drive and str(target).rstrip("\\").lower() == target.drive.lower():
        return None
    parent = target.parent
    if parent == target:
        return None
    return str(parent)


def get_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


# ──────────────────────────────────────────────────────────────────────────────
# LUCIDE SVG ICONS (Clean, Inline, Zero-CDN)
# ──────────────────────────────────────────────────────────────────────────────
ICON_HARD_DRIVE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" x2="2" y1="12" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" x2="6.01" y1="16" y2="16"/><line x1="10" x2="10.01" y1="16" y2="16"/></svg>'
ICON_FOLDER = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/></svg>'
ICON_FILE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><polyline points="14 2 14 8 20 8"/></svg>'
ICON_FILE_IMAGE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><polyline points="14 2 14 8 20 8"/><circle cx="10" cy="13" r="2"/><path d="m20 17-1.296-1.296a2.41 2.41 0 0 0-3.408 0L9 21"/></svg>'
ICON_FILE_AUDIO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 22h.5c.5 0 1-.2 1.4-.6.4-.4.6-.9.6-1.4V7.5L14.5 2H6c-.5 0-1 .2-1.4.6C4.2 3 4 3.5 4 4v3"/><polyline points="14 2 14 8 20 8"/><path d="M10 20v-1a2 2 0 1 1 4 0v1a2 2 0 1 1-4 0Z"/><path d="M6 20v-1a2 2 0 1 0-4 0v1a2 2 0 1 0 4 0Z"/><path d="M2 19v-3a6 6 0 0 1 12 0v3"/></svg>'
ICON_FILE_TEXT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><polyline points="14 2 14 8 20 8"/><line x1="10" x2="14" y1="13" y2="13"/><line x1="10" x2="14" y1="17" y2="17"/></svg>'
ICON_CHEVRON_RIGHT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>'
ICON_ARROW_UP_RIGHT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 7h10v10"/><path d="M7 17 17 7"/></svg>'
ICON_MORE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg>'

# ──────────────────────────────────────────────────────────────────────────────
# STREAMING & HTTP 206 RANGE REQUESTS
# ──────────────────────────────────────────────────────────────────────────────
def parse_range(header: str, size: int) -> Optional[Tuple[int, int]]:
    unit, _, spec = header.partition("=")
    if unit.strip().lower() != "bytes" or "," in spec:
        return None
    start_s, sep, end_s = spec.strip().partition("-")
    if not sep:
        return None
    try:
        if start_s == "":
            suffix = int(end_s)
            if suffix <= 0 or size == 0:
                raise ValueError
            return max(size - suffix, 0), size - 1
        start = int(start_s)
        end = int(end_s) if end_s != "" else None
    except ValueError:
        return None
    if start < 0:
        return None
    if start >= size:
        raise HTTPException(
            status_code=416,
            detail="Requested range not satisfiable",
            headers={"Content-Range": f"bytes */{size}"},
        )
    if end is None:
        end = size - 1
    if end < start:
        return None
    return start, min(end, size - 1)


def iter_file(path: Path, start: int, length: int) -> Iterator[bytes]:
    with open(path, "rb") as f:
        f.seek(start)
        remaining = length
        while remaining > 0:
            chunk = f.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk


@app.api_route(
    "/stream",
    methods=["GET", "HEAD"],
    dependencies=[Depends(require_login)],
)
def stream_media(path: str, request: Request):
    try:
        resolved = Path(path).resolve()
        if not resolved.exists() or not resolved.is_file():
            raise HTTPException(status_code=404, detail="File not found")
        stat = resolved.stat()
    except (PermissionError, OSError):
        raise HTTPException(status_code=403, detail="File inaccessible")

    size = stat.st_size
    mime = guess_mime(resolved)

    headers = {
        "Accept-Ranges": "bytes",
        "Last-Modified": formatdate(stat.st_mtime, usegmt=True),
        "Cache-Control": "private, max-age=3600",
        "ngrok-skip-browser-warning": "true",
    }
    if request.query_params.get("download") == "1":
        headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(resolved.name)}"

    start, end, status_code = 0, max(size - 1, 0), 200
    range_header = request.headers.get("range")
    if range_header and size > 0:
        parsed = parse_range(range_header, size)
        if parsed:
            start, end = parsed
            status_code = 206
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"

    length = (end - start + 1) if size > 0 else 0
    headers["Content-Length"] = str(length)

    if request.method == "HEAD":
        return Response(status_code=status_code, headers=headers, media_type=mime)

    return StreamingResponse(
        iter_file(resolved, start, length),
        status_code=status_code,
        media_type=mime,
        headers=headers,
    )


# ──────────────────────────────────────────────────────────────────────────────
# LOGIN ROUTE
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(render_template("login.html"), headers={"Cache-Control": "no-store"})


@app.post("/login")
def login_handler(data: _LoginData, request: Request):
    client_ip = get_client_ip(request)

    # Rate limiting check
    seconds_left = check_login_rate_limit(client_ip)
    if seconds_left is not None:
        mins = (seconds_left // 60) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Locked out for {mins} more minute(s).",
            headers={"Retry-After": str(seconds_left)},
        )

    # Server-side credential & 2FA PIN verification (constant time)
    user_ok = secrets.compare_digest(data.username.strip().encode("utf-8"), USERNAME.encode("utf-8"))
    pass_ok = secrets.compare_digest(data.password.encode("utf-8"), PASSWORD.encode("utf-8"))

    pin_ok = True
    if MEDIA_PIN:
        submitted_pin = (data.pin or "").strip()
        pin_ok = secrets.compare_digest(submitted_pin.encode("utf-8"), MEDIA_PIN.encode("utf-8"))

    if not (user_ok & pass_ok & pin_ok):
        attempts, locked_for = record_failed_login(client_ip)
        time.sleep(0.4)
        if locked_for > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts. Your IP has been temporarily locked out for 15 minutes.",
                headers={"Retry-After": str(locked_for)},
            )
        remaining = MAX_LOGIN_ATTEMPTS - attempts
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid credentials. ({remaining} attempt(s) remaining before temporary lockout)",
        )

    clear_failed_logins(client_ip)

    # Issue httpOnly cookie
    response = JSONResponse({"success": True})
    response.set_cookie(
        key="session",
        value=create_session_token(data.username.strip()),
        httponly=True,
        samesite="lax",
        path="/",
        max_age=SESSION_MAX_AGE,
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session", path="/")
    return response


# ──────────────────────────────────────────────────────────────────────────────
# DASHBOARD (Clean Separation: Hub vs Explorer)
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_login)])
def dashboard(path: Optional[str] = None):
    lan_ip = get_local_ip()

    # ──────────────────────────────────────────────────────────────────────────
    # VIEW 1: STORAGE HUB (when visiting root '/' without path argument)
    # ──────────────────────────────────────────────────────────────────────────
    if not path and not DEFAULT_PATH:
        drives = get_available_drives()
        drive_cards = []
        for d in drives:
            used_gb = d["used"] / (1024**3)
            total_gb = d["total"] / (1024**3)
            encoded_path = quote(d["path"])
            drive_cards.append(
                f'<a class="drive-card" href="/?path={encoded_path}">'
                f'<div class="drive-card-top">'
                f'<div class="drive-icon {d["tone"]}">{ICON_HARD_DRIVE}</div>'
                f'<span class="drive-card-more">{ICON_MORE}</span>'
                f'</div>'
                f'<h2>{html.escape(d["name"])}</h2>'
                f'<p class="drive-path">{html.escape(d["path"])}</p>'
                f'<div class="capacity">'
                f'<div class="capacity-track"><span style="width:{d["percent"]}%;"></span></div>'
                f'<div class="capacity-meta"><span>{used_gb:.1f} GB used</span><span>{total_gb:.1f} GB</span></div>'
                f'</div>'
                f'</a>'
            )

        shortcuts = get_quick_shortcuts()
        shortcut_items = []
        for s in shortcuts:
            encoded_path = quote(s["path"])
            shortcut_items.append(
                f'<a class="shortcut" href="/?path={encoded_path}">'
                f'{ICON_FOLDER}'
                f'<span>{html.escape(s["name"])}</span>'
                f'<small>{html.escape(s["count"])}</small>'
                f'{ICON_CHEVRON_RIGHT}'
                f'</a>'
            )

        return HTMLResponse(
            render_template(
                "hub.html",
                lan_ip=lan_ip,
                username=html.escape(USERNAME),
                avatar_letter=html.escape(USERNAME[0].upper()),
                drive_cards="".join(drive_cards) if drive_cards else '<div class="empty-notice">No drives detected</div>',
                shortcut_items="".join(shortcut_items),
            ),
            headers={"Cache-Control": "no-store"},
        )

    # ──────────────────────────────────────────────────────────────────────────
    # VIEW 2: FILE EXPLORER VIEW (when a folder path or drive is selected)
    # ──────────────────────────────────────────────────────────────────────────
    target_dir = normalize_target_path(path)

    # 1. Breadcrumbs
    crumbs = build_breadcrumbs(target_dir)
    crumb_elements = []
    for i, (label, cpath) in enumerate(crumbs):
        if i == len(crumbs) - 1:
            crumb_elements.append(f'<strong>{html.escape(label)}</strong>')
        else:
            crumb_elements.append(f'<a href="/?path={quote(cpath)}">{html.escape(label)}</a>')
            crumb_elements.append(ICON_CHEVRON_RIGHT)

    # 2. Up Button
    parent_path = get_parent_path(target_dir)
    up_button_html = (
        f'<a class="up-button" href="/?path={quote(parent_path)}" title="Go up to {html.escape(parent_path)}" aria-label="Go up">{ICON_ARROW_UP_RIGHT}</a>'
        if parent_path else ""
    )

    # 3. Read Folder Contents
    subfolders = []
    files = []
    try:
        with os.scandir(target_dir) as entries:
            for entry in entries:
                if is_hidden_or_system(entry.name):
                    continue
                try:
                    if entry.is_dir(follow_symlinks=False):
                        count_str = count_folder_items(Path(entry.path))
                        subfolders.append((entry.path, entry.name, count_str))
                    elif entry.is_file(follow_symlinks=False):
                        ext = Path(entry.name).suffix.lower()
                        if ext in _SKIP_EXTENSIONS:
                            continue
                        stat = entry.stat()
                        files.append((entry.path, entry.name, stat.st_size, stat.st_mtime))
                except (PermissionError, OSError):
                    continue
    except (PermissionError, OSError):
        pass

    subfolders.sort(key=lambda s: s[1].lower())
    files.sort(key=lambda f: f[1].lower())

    # Build Folder Items
    folder_elements = []
    for fpath, fname, fcount in subfolders:
        folder_elements.append(
            f'<a class="folder-item" data-name="{html.escape(fname.lower(), quote=True)}" href="/?path={quote(fpath)}">'
            f'{ICON_FOLDER}'
            f'<span>{html.escape(fname)}</span>'
            f'<small>{html.escape(fcount)}</small>'
            f'</a>'
        )

    # Build File Rows
    file_elements = []
    for full_path, fname, fsize, fmtime in files:
        ext = Path(fname).suffix.lower()
        mime = guess_mime(Path(fname))
        ext_clean = ext.lstrip(".").upper() or "FILE"

        if mime.startswith("video/"):
            kind = "video"
            icon = ICON_FILE_IMAGE
        elif mime.startswith("image/"):
            kind = "image"
            icon = ICON_FILE_IMAGE
        elif mime.startswith("audio/"):
            kind = "audio"
            icon = ICON_FILE_AUDIO
        elif ext == ".pdf":
            kind = "pdf"
            icon = ICON_FILE_TEXT
        else:
            kind = "file"
            icon = ICON_FILE

        stream_url = "/stream?path=" + quote(full_path) + "&ngrok-skip-browser-warning=1"
        escaped_name = html.escape(fname)
        mtime_display = format_mtime(fmtime)
        size_display = human_size(fsize)

        file_elements.append(
            f'<button type="button" class="file-row" '
            f'data-name="{html.escape(fname.lower(), quote=True)}" '
            f'data-url="{stream_url}" '
            f'data-kind="{kind}" '
            f'data-mime="{mime}" '
            f'data-type="{ext_clean}" '
            f'data-size="{size_display}" '
            f'data-title="{escaped_name}">'
            f'<div class="file-icon">{icon}</div>'
            f'<div class="file-name"><strong>{escaped_name}</strong><span>{mtime_display}</span></div>'
            f'<span class="file-type">{ext_clean}</span>'
            f'<span class="file-size">{size_display}</span>'
            f'<span class="file-more">{ICON_MORE}</span>'
            f'</button>'
        )

    folder_html = "".join(folder_elements) if folder_elements else '<div class="empty-notice">No subfolders in this directory</div>'
    file_html = "".join(file_elements) if file_elements else '<div class="empty-notice">No media or files in this directory</div>'

    return HTMLResponse(
        render_template(
            "explorer.html",
            lan_ip=lan_ip,
            username=html.escape(USERNAME),
            avatar_letter=html.escape(USERNAME[0].upper()),
            breadcrumbs="".join(crumb_elements),
            up_button=up_button_html,
            total_count=len(subfolders) + len(files),
            folder_count_padded=str(len(subfolders)).zfill(2),
            folder_cards=folder_html,
            file_count_padded=str(len(files)).zfill(2),
            file_rows=file_html,
        ),
        headers={"Cache-Control": "no-store"},
    )


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = Path(sys.argv[1]).resolve()
        if target.is_dir():
            DEFAULT_PATH = str(target)
        else:
            print(f"⚠ Warning: '{sys.argv[1]}' is not a valid directory.")

    local_ip = get_local_ip()
    drives = [d["name"] for d in get_available_drives()]
    pwd_warnings = audit_password_strength(PASSWORD)
    print("=" * 65)
    print(" 📺 Local Media Server & Windows Drive Explorer")
    if DEFAULT_PATH:
        print(f" Default Folder  : {DEFAULT_PATH}")
    print(f" Detected Drives : {', '.join(drives)}")
    print(f" Open on PC      : http://localhost:{PORT}")
    print(f" Open on Phone   : http://{local_ip}:{PORT}")
    print(f" Login Account   : {USERNAME} / {'*' * len(PASSWORD)}")
    if MEDIA_PIN:
        print(f" 2FA Security PIN: {MEDIA_PIN}")
    print("=" * 65)
    if pwd_warnings:
        print(" ⚠  SECURITY WARNING(S):")
        for w in pwd_warnings:
            print(f"    - {w}")
        print("=" * 65)
    uvicorn.run(app, host=HOST, port=PORT)