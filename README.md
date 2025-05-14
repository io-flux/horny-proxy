![Logo Placeholder](static/logo-placeholder@0.5x.png)

**HornyProxy** 🍒 is a FastAPI microservice for securely sharing videos from your Stash adult media platform. It offers a no frills dark UI for playback and a secure admin panel with JWT authentication to manage your private shares.

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

## Install & configure

1. Clone the repo:

```bash
git clone https://github.com/io-flux/horny-proxy
cd horny-proxy
```

2. Get dependencies

a. Either use `mamba` or `conda` (recommended):

```bash
mamba create -n hornyproxy python=3.8 fastapi uvicorn requests pyyaml sqlalchemy pydantic python-jose cryptography passlib
mamba activate hornyproxy
```

b. Or just use `pip`:

```
# Ensure you are in `/path/to/horny-proxy`
pip install -r requirements.txt
```

3. Fill in your details in `config.yaml`:

```
# Ensure you are in `/path/to/horny-proxy`
# Optional: start with the example configuration:
cp example-config.yaml config.yaml

# Use nano or your preferred text editor:
nano config.yaml
```


```yaml
horny:
  # host specifies which interface horny-proxy will bind to; then pick an open port
  # 127.0.0.1 will only be available locally (or over a local reverse proxy)
  # 0.0.0.0 will be available to anyone that can reach your device on the port specified below
  host: "127.0.0.1"
  port: 6669

  # base_domain is used to generate share links
  base_domain: "https://example.com"

  # username and password for creating / managing shares
  admin_username: "admin"
  admin_password: "your_secure_password"

  # default resolution when creating a new share
  default_resolution: "MEDIUM"  # LOW, MEDIUM, HIGH

  # the length of the UUID generated for new shares, e.g., 8 characters might look like `https://horny-proxy.club/share/gkCXaxGw`
  share_id_length: 8

stash:
  # the IP address and port of your stash instance
  server_ip: "127.0.0.1"
  port: 999

  # your stash instance's API key
  api_key: "yourStashAPIKeyHere"

# text displayed below player on video shares
disclaimer: "For private use only. No unauthorized sharing."
```

4. Optional: customize logo 

Add your personal logos in `static/localized/` (e.g., `logo.png`, `logo@2x.png`). 

Without them, default placeholders in `static/` are used.

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

