![Logo Placeholder](static/logo-placeholder@0.5x.png)

# 🍒 Horny Proxy - Share Your Stash with Style

**HornyProxy** is a sleek, secure proxy service for sharing videos from your Stash collection. Built with FastAPI and wrapped in a gorgeous purple-themed UI, it's the premium way to share your private content with trusted viewers.

## 🔥 What's New

We've completely redesigned Horny Proxy with a focus on aesthetics and functionality:

### 💜 Purple Passion UI
- **Dark Mode Design**: Sultry purple/pink/red color scheme that's easy on the eyes
- **Glassmorphism Effects**: Modern frosted glass aesthetics with subtle animations
- **Full-Window Admin Panel**: Responsive 2x2 grid layout that maximizes screen space
- **Mobile-First**: Looks stunning on every device

### 🏷️ Tag Sharing System
Share entire collections with a single link:
- Group videos by tag for themed collections
- Custom share IDs for memorable URLs
- Gallery view with cached thumbnails
- Individual video playback within collections

### 🏠 Public Gallery
- Curated homepage for featured content
- Lazy-loading infinite scroll
- Collection badges for tag shares
- No passwords allowed (keeps it family-friendly 😉)

## 🚀 Key Features

| Feature | Description |
|:--------|:------------|
| **Smooth Playback** | Video.js player with variable speed control (0.5x-2x) |
| **Admin Dashboard** | Comprehensive share management interface |
| **Secure Sharing** | Password-protected, expiring links |
| **Resolution Control** | Choose streaming quality: LOW, MEDIUM, or HIGH |
| **Hit Tracking** | Anonymous view counting for analytics |
| **Smart Time Display** | Relative expiration times (30m, 8h, 7d) |

## 🔧 Installation & Setup

### Prerequisites
* Python 3.8+
* Mamba/Conda or pip
* Running Stash instance with API access

### Quick Start

1. **Clone the repository:**
```bash
git clone https://github.com/io-flux/horny-proxy
cd horny-proxy
```

2. **Set up your environment:**

Using mamba (recommended):
```bash
mamba create -n hornyproxy python=3.8 fastapi uvicorn requests pyyaml sqlalchemy pydantic python-jose cryptography passlib jinja2
mamba activate hornyproxy
```

Or with pip:
```bash
pip install -r requirements.txt
```

3. **Configure your instance** in `config.yaml`:
```yaml
horny:
  host: "127.0.0.1"
  port: 6669                         # Nice
  base_domain: "https://family.fun"  # Your domain here
  admin_username: "daddy"
  admin_password: "your_secure_password"
  default_resolution: "MEDIUM"
  share_id_length: 8

stash:
  server_ip: "127.0.0.1"
  port: 9999
  api_key: "your_stash_api_key"

# This is not legal advice but you might consider adopting a no-nonsense disclaimer if there is any chance of anyone outside your family seeing it
disclaimer: "This content is shared for private use only. Unauthorized distribution is prohibited. This site does not encourage/condone illegal sexual conduct and is intended solely to provide visual pleasure for ADULTS only. Please leave this site if you are under 18 or if you find mature/explicit content offensive. All mature/explicit content on this site is strictly in compliance with 18 U.S.C. § 2257, i.e., all performers featured are 18 years or older of age. This site and all its associated domains being in accordance with 17 U.S.C. § 512 and the Digital Millennium Copyright Act, responds to infringement notices within 24 hours."
"
```

4. **Add your branding:**
- Place your logo in `static/localized/` (logo.png, logo@2x.png, logo@3x.png)
- The purple theme is pre-configured and ready to use

## 💜 Admin Panel

Access the admin panel at `http://stashtube.xxx/__admin`  # enter your domain here

### Video Sharing
1. Enter Stash video ID or use "Lookup" for auto-fill
2. Set expiration (1-365 days)
3. Choose resolution and optional password
4. Toggle "Feature on Home?" for gallery display
5. Copy your share link

### Tag Collections
1. Enter a tag name to find matching content
2. Click "Lookup" to verify the tag exists
3. Choose share ID type:
   - **Random**: Auto-generated unique ID
   - **Tag Name**: Uses the tag as the URL path
   - **Custom**: Create your own memorable URL
4. Configure options and share

### Share Management
- **Real-time Stats**: View hit counts and expiration times
- **Quick Actions**: Copy, edit, or delete shares
- **Bulk Refresh**: Update all data with one click

## 🎬 Viewing Experience

### Video Player
- Clean, modern player with purple-themed controls
- Full metadata display:
  - Performer information with social links
  - Tag system with visual pills
  - Studio details
  - External URLs
- Password protection with styled modal
- Responsive design for all devices

### Gallery Features
- Smooth infinite scroll
- Hover animations with subtle sheen effects
- Collection indicators for tag shares
- Fast-loading cached thumbnails

## 🔒 Security & Privacy

- **JWT Authentication**: Secure admin access
- **Password Protection**: Optional per-share passwords
- **Auto-Expiration**: Links expire on schedule
- **API Key Protection**: Stash credentials stay private
- **Anonymous Tracking**: No personal data collected

## 🎨 Customization

### Branding Options
1. **Logo**: Support for high-DPI displays
2. **Disclaimer**: Configurable legal text
3. **Domain**: Set your base URL for proper links
4. **Gallery**: Curate your public content

### Example Screenshots
<div style="display: flex; justify-content: center; align-items: center; gap: 20px; padding: 10px;"><a href="https://github.com/io-flux/horny-proxy/raw/main/static/screenshot1.jpg"><img src="https://github.com/io-flux/horny-proxy/raw/main/static/screenshot1.jpg?raw=true" alt="Admin back end screenshot" width="300" style="border: 2px solid #ff69b4; border-radius: 5px;"></a> <a href="https://github.com/io-flux/horny-proxy/raw/main/static/screenshot2.jpg?"><img src="https://github.com/io-flux/horny-proxy/raw/main/static/screenshot2.jpg?raw=true" alt="Tag front end screenshot" width="300" style="border: 2px solid #ff69b4; border-radius: 5px;"></a></div>


### Advanced Features
- Memorable custom share IDs
- Tag-based bulk sharing
- Per-share resolution settings
- Flexible expiration periods

## 🚨 Troubleshooting

**Login Issues?**
Clear your browser cache and localStorage, then try again.

**Videos Not Playing?**
Verify your Stash API key and server accessibility.

**How to Share Collections?**
Tag your videos in Stash, then use the tag sharing feature.

**Missing Thumbnails?**
Horny Proxy will cache them on first access.

## 📝 Recent Updates

- **Tag Sharing**: Share entire collections, not just individual videos
- **Purple UI Overhaul**: Modern dark theme with glassmorphism
- **Responsive Admin**: Full-window 2x2 grid layout
- **Public Gallery**: Showcase selected content
- **Smart Time Display**: Human-readable expiration times
- **Rich Metadata**: Complete video details from Stash

## 🤝 Contributing

We welcome contributions! Feel free to open issues or submit pull requests.

## ⚖️ Legal Notice

Users are responsible for ensuring all shared content complies with applicable laws. All performers must be 18+. See the configured disclaimer for detailed terms.

---

*Built with 💜 for the discerning content curator*

