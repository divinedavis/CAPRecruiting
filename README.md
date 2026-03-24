# CAP Recruiting

A football recruiting platform connecting high school players with college coaches.

**Live site:** [caprecruiting.com](https://caprecruiting.com)

## What It Does

CAP Recruiting gives high school football players a professional recruiting profile that coaches can discover and evaluate. Players control how much of their profile is visible by choosing a subscription tier — the higher the tier, the more coaches can see. Coaches get free access to browse and evaluate players.

### Player Tiers

| Tier | Price | What Coaches See |
|------|-------|-----------------|
| **Free** | — | Visitors only — preview cards, no profile access |
| **Essentials** | $10/mo | Profile photo, overview, field & lifting stats |
| **Advanced** | $25/mo | + Transcripts, photo gallery, scholarship offers, campus visits |
| **Premium** | $50/mo | + Highlight videos, contact info, direct messaging |

Subscriptions are handled via Stripe. Players choose a plan on signup and can upgrade or cancel anytime.

---

## Features

### Player Profiles
- Personal info — name, school, city/state, class year
- **Player Overview** — height, weight, wingspan, GPA, NCAA eligibility #, intended major
- **Field Stats** — 40-yard dash, pro agility, vertical, broad jump
- **Lifting Stats** — bench press, squat, clean
- Profile photo upload
- Bio, social links (Hudl, X/Twitter, Instagram)
- External links (MaxPreps, highlight reels, custom)
- Scholarship offers (up to 5) and campus visits (up to 5)

### Coach Profiles
- School, title, division, conference, bio
- External links

### Photos
- Players upload up to 20 photos; coaches see them on Advanced+ players
- In-page lightbox with keyboard navigation
- Grid preview with "Show All" expand

### Transcripts
- Players upload up to 4 transcripts (PDF, DOC, DOCX)
- Visible to coaches on Advanced+ players only
- In-page viewer — PDFs embed directly, DOCX via Google Docs viewer

### Videos
- Players upload and pin highlight videos (up to 5)
- Visible to coaches on Premium players only

### Messaging
- Coaches can message Premium-tier players (coach-initiated only)
- Real-time WebSocket chat with unread message badges

### Subscriptions (Stripe)
- Players choose Essentials / Advanced / Premium on signup
- Stripe Checkout for payment, Customer Portal for self-serve cancel/upgrade
- Webhooks auto-update player tier on payment success, failure, or cancellation
- Admins can manually override any player's tier from the admin panel

### Admin Panel
- Full user management — view, edit, delete any account
- Manually set subscription tier for any player
- Star ratings (0–5) visible on profiles and player directory
- Coach evaluations — visible to coaches and admins only
- Team management and coach invite links
- Email notification on every new player signup

### Player Directory
- Visitors can browse player cards without signing up
- Filter by school, position, and class year
- Player cards show avatar, position, stats, offers, and star rating
- Visitors cannot click into profiles (login required)

### Auth & Accounts
- Player signup requires selecting a paid tier (no free tier for registered players)
- Coach signup requires an admin-issued invite link
- Login with username or email
- Password reset via email

### Performance & SEO
- All media served via DigitalOcean Spaces CDN
- Open Graph + Twitter Card meta tags on every profile
- Gzip compression via Nginx
- Lazy loading on all image grids

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | FastAPI (Python) |
| Database | SQLite via SQLAlchemy ORM |
| Templates | Jinja2 |
| Server | Uvicorn (ASGI, 2 workers) |
| Reverse proxy | Nginx |
| SSL | Let's Encrypt / Certbot |
| Real-time | WebSockets |
| Auth | Starlette SessionMiddleware + bcrypt |
| Payments | Stripe (Checkout, Customer Portal, Webhooks) |
| File storage | DigitalOcean Spaces (S3-compatible) via boto3 + CDN |
| Email | aiosmtplib (Gmail SMTP) |
| Process manager | systemd |
| Hosting | DigitalOcean Droplet (NYC3) |
