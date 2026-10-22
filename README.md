# 📺 Home Media Server

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, self-hosted local network media server and drive explorer built with **FastAPI** and modern **Vanilla CSS/JS**. Stream your personal video and audio library across PCs, phones, and tablets on your local network with zero external frontend dependencies.

---

## ✨ Features

- ⚡ **HTTP 206 Partial-Content Streaming**: Instant video scrub, seek, fast-forward, and rewind without buffering the entire file.
- 🗄️ **Storage Hub & Drive Explorer**: Automatically detects connected Windows drives (`C:\`, `D:\`, `E:\`, etc.) with real-time capacity meters and quick shortcuts.
- 🎬 **Theater Mode Lightbox**: Built-in modal media player for videos, music, and images. Includes graceful fallbacks for formats requiring external desktop players like VLC (`.mkv`, `.avi`, HEVC/AC-3).
- 🎨 **Minimal Swiss Editorial UI**: Clean monochrome design system inspired by Linear and modern minimalism. Zero heavy frameworks (React/Vue/Tailwind) — pure, lightning-fast HTML5, CSS3, and ES6 JavaScript.
- 🔍 **Live Client-Side Search & Grid/List View**: Filter files and folders instantly as you type; switch between comfortable grid cards and compact list rows.

---

## 🔒 Security Hardening

Built from the ground up to prevent common web application vulnerabilities:

1. **Anti-Brute Force IP Rate Limiter**: Automatically locks out IP addresses for 15 minutes after 5 consecutive failed login attempts.
2. **Two-Factor Authentication (2FA PIN)**: Optional 6-digit secondary security key verified with constant-time string comparison (`secrets.compare_digest`) to prevent timing attacks.
3. **HTTP-Only Session Cookies**: Authenticated sessions are signed with timestamped SHA-256 HMAC tokens and stored in `httpOnly`, `SameSite=Lax` cookies, preventing XSS token theft.
4. **Password Strength & Breach Auditing**: Checks credentials on startup against common dictionary/breached passwords and warns if your password is too weak.
5. **Path Traversal Protection**: Prevents directory traversal attacks (`../`) and hides sensitive OS system files (`$Recycle.Bin`, `System Volume Information`, etc.).

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/abdulrehman1610/home-media-server.git
cd home-media-server
```

### 2. Set up a virtual environment (optional but recommended)
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux / macOS:
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
Copy the example template to `.env`:
```bash
cp .env.example .env
```
Edit `.env` with your desired credentials:
```env
MEDIA_USER=your_username
MEDIA_PASS=your_password
MEDIA_PIN=123456
MEDIA_HOST=0.0.0.0
MEDIA_PORT=8000
DEFAULT_PATH=
```

### 5. Launch the server
```bash
python mediaServer2.py
# or using uvicorn directly:
uvicorn mediaServer2:app --host 0.0.0.0 --port 8000 --reload
```

Open your browser at:
- **On this computer**: `http://localhost:8000`
- **On phones / tablets on the same Wi-Fi**: `http://<your-pc-ip>:8000`

---

## ⚙️ Configuration (`.env`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MEDIA_USER` | `admin` | Login username |
| `MEDIA_PASS` | `ChangeThisPassword123!` | Login password |
| `MEDIA_PIN` | `123456` | 6-digit 2FA security PIN (leave blank to disable) |
| `MEDIA_HOST` | `0.0.0.0` | Network interface to bind (`0.0.0.0` for all local interfaces) |
| `MEDIA_PORT` | `8000` | Port to run the server on |
| `DEFAULT_PATH` | *(None)* | Optional initial directory path (e.g. `D:\Movies` or `C:\Users\Username\Videos`) |

---

## 📁 Project Structure

```text
home-media-server/
├── mediaServer2.py       # FastAPI backend (routing, authentication, streaming logic)
├── requirements.txt      # Python dependencies
├── .env.example          # Environment variables template
├── .gitignore            # Git exclusion rules
├── README.md             # Project documentation
├── static/
│   ├── style.css         # Minimalist editorial design system
│   └── app.js           # Client controller (search, view toggle, lightbox player)
└── templates/
    ├── login.html        # Secure authentication gate
    ├── hub.html          # Storage Hub view (connected drives & shortcuts)
    └── explorer.html     # File explorer view (breadcrumbs, files, theater stage)
```

---

## 🎥 Media Format Support

| Container / Codec | Browser Playback | External Player (VLC / PotPlayer) |
| :--- | :---: | :---: |
| **MP4 (H.264 / AAC)** | ✅ Native | ✅ Native |
| **WebM (VP8/VP9)** | ✅ Native | ✅ Native |
| **MKV / AVI / WMV** | ⬇️ Fallback with 1-Click VLC / Download | ✅ Native |
| **MP3 / WAV / FLAC** | ✅ Native | ✅ Native |
| **PNG / JPG / WEBP** | ✅ Native | ✅ Native |

> [!TIP]
> Modern web browsers do not natively decode `.mkv` or `.avi` files or audio encoded in AC-3/DTS. When clicking an unsupported format, the server UI automatically displays a direct **Open in VLC** button and a **Direct Download** link.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
