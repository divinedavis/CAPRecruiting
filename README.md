# Bearcats Recruiting

A football recruiting platform connecting high school players with college coaches.

**Live site:** [bearcatrecruiting.com](https://bearcatrecruiting.com)

## Features

### Player Profiles
- Personal info — first/last name, school, city/state, class year
- **Player Overview** — height, weight, GPA, class year
- **Field Stats** — 40-yard dash, pro agility (sec), vertical, broad jump (in)
- **Lifting Stats** — bench press, squat, clean (lbs)
- Profile photo upload
- Bio, social links (Hudl, X/Twitter, Instagram)
- External links (MaxPreps, highlight reels, custom)
- Scholarship offers and campus visits

### Coach Profiles
- School, title, division, conference, bio
- External links

### Photos
- Players and admins can upload up to 20 photos per profile
- In-page lightbox viewer with previous/next navigation and keyboard support
- Grid preview showing 5 photos with "Show All" button
- Multi-photo selection on upload

### Transcripts
- Players and admins can upload up to 4 transcripts per profile (PDF, DOC, DOCX)
- In-page viewer — PDFs embed directly, DOCX uses Google Docs viewer
- Visible to coaches and admins only

### Videos
- Players can upload and pin highlight videos
- Pinned video shown first on profile

### Messaging
- Real-time WebSocket chat between any two users
- Unread message badge showing count of unique senders

### Admin Panel
- Full user management — view, edit, and delete any account
- Edit any player or coach profile via `/admin/users/{id}/edit-profile`
- Upload/delete photos, transcripts, and videos for any player
- **Star ratings** — admins can assign 0–5 stars to players, visible on profiles and the player directory
- Coach evaluations — visible to coaches and admins only
- Team management

### Player Directory
- Visitors can browse players by team without signing up
- Filter by class year (dropdown) after selecting a team
- Player cards show avatar, position, stats, offers, and star rating
- Social icons (Hudl, X, Instagram) on each card

### Auth & Accounts
- Sign up as player or coach
- Login with username or email
- Admin accounts with elevated permissions
- Delete account (admin only)

### Performance
- Images resized and compressed on upload (max 1200px, JPEG 82%)
- Lazy loading on all image grids
- All media (photos, videos, transcripts) served via DigitalOcean Spaces CDN

### Sharing
- Open Graph + Twitter Card meta tags on every page
- Player profiles generate preview cards with photo, name, and position
- iMessage / social share preview with site logo

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python) |
| Database | SQLite via SQLAlchemy |
| Templates | Jinja2 |
| Server | Uvicorn (ASGI, 2 workers) |
| Reverse proxy | Nginx |
| SSL | Let's Encrypt / Certbot |
| Real-time | WebSockets |
| Auth | Starlette SessionMiddleware + bcrypt |
| File storage | DigitalOcean Spaces (S3-compatible) + CDN |
| Image processing | Pillow |
| Process manager | systemd |
| Hosting | DigitalOcean Droplet |

## Project Structure

```
bearcats/
├── main.py                  # FastAPI app — routes, models, WebSocket logic
├── requirements.txt         # Python dependencies
├── recruiting.db            # SQLite database
├── static/
│   ├── style.css            # All styles (responsive, mobile-friendly)
│   ├── cap-logo.png         # Site logo
│   ├── og-default.png       # Open Graph / iMessage share image
│   ├── hudl.png             # Hudl icon
│   ├── x_logo.svg           # X (Twitter) icon
│   └── instagram_logo.svg   # Instagram icon
└── templates/
    ├── base.html            # Navbar, footer, global WebSocket badge
    ├── home.html            # Landing page
    ├── team_select.html     # Team browser for visitors
    ├── dashboard.html       # Player directory with filters
    ├── signup.html          # Registration with role selection
    ├── login.html           # Login (username or email)
    ├── profile.html         # Public profile view (player & coach)
    ├── edit_profile.html    # Edit profile, photos, videos, transcripts
    ├── transcript_view.html # Transcript viewer page
    ├── inbox.html           # Message thread list
    ├── conversation.html    # Real-time chat
    ├── admin_teams.html     # Admin team management
    └── admin_users.html     # Admin user management
```
