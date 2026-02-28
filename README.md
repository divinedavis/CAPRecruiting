# Bearcats Recruiting

A football recruiting platform connecting players with college coaches.

**Live site:** [bearcatrecruiting.com](https://bearcatrecruiting.com)

## Features

- **Player profiles** — height, weight, 40-yard dash, bench press, vertical, GPA, position, class year, school, city/state, bio
- **Coach profiles** — school, title, division, conference, bio
- **Profile photos** — players and coaches can upload a profile picture
- **Direct messaging** — real-time WebSocket chat between any two users
- **Unread badge** — shows count of unique senders with unread messages
- **Shareable profiles** — one-click copy profile link, with iOS iMessage / Open Graph preview support
- **External links** — link to Hudl, MaxPreps, highlight reels, or any external site
- **Public player directory** — visitors can browse and view profiles without signing up
- **Username validation** — no spaces or special characters allowed

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python) |
| Database | SQLite via SQLAlchemy |
| Templates | Jinja2 |
| Server | Uvicorn (ASGI) |
| Reverse proxy | Nginx |
| SSL | Let's Encrypt / Certbot |
| Real-time | WebSockets |
| Auth | Starlette SessionMiddleware + bcrypt |
| Process manager | systemd |

## Project Structure

```
bearcats/
├── main.py              # FastAPI app — routes, models, WebSocket logic
├── requirements.txt     # Python dependencies
├── static/
│   └── style.css        # All styles (responsive, mobile-friendly)
└── templates/
    ├── base.html        # Navbar, footer, global WebSocket badge
    ├── home.html        # Landing page
    ├── dashboard.html   # Public player directory
    ├── signup.html      # Registration with role selection
    ├── login.html       # Login
    ├── profile.html     # Public profile view (player & coach)
    ├── profile_edit.html# Edit your own profile
    ├── inbox.html       # Message thread list
    └── conversation.html# Real-time chat with AJAX send + WS fallback
```

## Running Locally

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8080
```

## Deployment

The app runs on a DigitalOcean droplet behind Nginx with SSL termination.

- **Service:** `systemctl status bearcats`
- **Logs:** `journalctl -u bearcats -f`
- **Nginx config:** `/etc/nginx/sites-enabled/bearcats`

## Tests

```bash
source venv/bin/activate
python test_comprehensive.py   # 109 tests — all features end-to-end
python test_bearcats.py        # Basic route tests
python test_photos.py          # Photo upload tests
python test_visitor.py         # Public access tests
```
