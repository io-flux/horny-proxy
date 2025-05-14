# HornyProxy 🍒

![Logo Placeholder](static/logo-placeholder@0.5x.png)

HornyProxy is a FastAPI app for securely sharing videos from your Stash adult media platform. It offers a sleek UI for playback and a secure admin panel with JWT authentication to manage your private shares.

## Key Features

| Feature | Description |
|:--------|:------------|
| **Public Playback** | Smooth Video.js player with seeking, speed control (0.5x-2x), and fullscreen mode |
| **Admin Panel** | Easily create, edit, delete, and track hits on shared links |
| **Secure Sharing** | Unique, expiring links with optional password protection |
| **Resolution Options** | Choose streaming quality: LOW, MEDIUM, or HIGH |
| **Stash Integration** | Streams content from Stash without exposing API keys |

## Prerequisites

* Python 3.8+
* Mamba (or Conda) for environment management
* Running Stash instance with API access
* Logo images for branding

## Installation

1. Set up a Mamba environment:

```bash
mamba create -n hornyproxy python=3.8 fastapi uvicorn requests pyyaml sqlalchemy pydantic python-jose cryptography passlib
mamba activate hornyproxy
```

2. Create the project structure:

```bash
mkdir hornyproxy
cd hornyproxy
mkdir -p static/shares
```

3. Add `hornyproxy.py`, `config.yaml`, and static files to the directories.

## Configuration

Create `config.yaml` in the project root:

```yaml
horny:
  host: "127.0.0.1"
  port: 6669
  base_domain: "https://example.com"
  admin_username: "admin"
  admin_password: "your_secure_password"
  default_resolution: "MEDIUM"  # LOW, MEDIUM, HIGH
  share_id_length: 8
stash:
  server_ip: "127.0.0.1"
  port: 5588
  api_key: "yourStashAPIKeyHere"
disclaimer: "For private use only. No unauthorized sharing."
```

## Static Files

| File | Description |
|:-----|:------------|
| `static/admin.html` | Admin panel interface |
| `static/admin.js` | Admin panel JavaScript |
| `static/styles.css` | Custom styling for interfaces |
| `static/video-player.html` | Video player template |
| `static/password-prompt.html` | Password protection template |
| `static/logo.png` | Default logo placeholder (with @2x, @3x options) |

**Customization Note**: Add your personal logos in `static/localized/` (e.g., `logo.png`, `logo@2x.png`). Without them, default placeholders in `static/` are used.

## Usage

1. Start the server:

```bash
python hornyproxy.py
```

Add `--debug` for detailed logs:

```bash
python hornyproxy.py --debug
```

2. Server runs on the host/port in `config.yaml` (default: http://127.0.0.1:6669).

3. Access the admin panel:
   - Open http://127.0.0.1:6669/static/admin.html
   - Log in with configured credentials

4. Share a video:
   - Enter video name or fetch title from Stash
   - Add Stash ID, validity days, resolution, and optional password
   - Click "Share" and copy the link

5. Watch the content:
   - Open the share URL and enter password if required 😘

## Security & Customization 🔒

| Feature | Description |
|:--------|:------------|
| **JWT Authentication** | Admin access is securely protected |
| **Password Protection** | Optional safeguard for individual shares |
| **Expiring Links** | Shares auto-expire for added safety |
| **No API Exposure** | Keeps your Stash API key hidden |

**Make It Yours**: Add your logo at `static/localized/logo.png` (with @2x, @3x for crispness), edit the disclaimer in `config.yaml`, and tweak `static/styles.css` to style your spicy setup 🍓.

