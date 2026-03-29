# CAP Recruiting (caprecruiting.com)

Football recruiting platform connecting high school players with college coaches. Players create profiles with stats, photos, videos, and transcripts. Coaches browse and message players based on subscription tier visibility.

## Tech Stack

- **Backend:** FastAPI (Python 3.12), single-file app (`main.py`, ~2700 lines)
- **Database:** SQLite (`recruiting.db`), SQLAlchemy ORM
- **Templates:** Jinja2, all extend `base.html`
- **Server:** Uvicorn with 2 workers, behind Nginx reverse proxy
- **Domain:** caprecruiting.com (SSL via Let's Encrypt)
- **Payments:** Stripe (Checkout Sessions, Customer Portal, Webhooks)
- **File Storage:** DigitalOcean Spaces (videos, images, transcripts), local `static/uploads/` for profile photos
- **Email:** Gmail SMTP (aiosmtplib for async)
- **Process:** systemd service `bearcats.service`, runs as OS user `bearcats`

## Subscription Tiers

```
free (0) → essentials (1) → advanced (2) → premium (3)
```

- Gating is on the **player's** tier, not the viewer's — coaches/admins always see what the player's tier allows
- `tier_gte(tier, required)` helper for tier checks
- Admins always treated as premium
- In-person payment bypass: admin generates token, player gets premium until expiry (cron handles downgrade)

### Tier Visibility

| Feature | Essentials | Advanced | Premium |
|---------|-----------|----------|---------|
| Profile photo + stats | Yes | Yes | Yes |
| Photo gallery + offers | No | Yes | Yes |
| Transcripts | No | Yes | Yes |
| Videos | No | No | Yes |
| Contact info | No | No | Yes |
| Coach messaging | No | No | Yes |
| Questionnaires page | No | No | Yes |

## Database Tables

`users`, `player_profiles`, `coach_profiles`, `teams`, `videos`, `photos`, `profile_images`, `transcripts`, `evaluations`, `messages`, `legal_contracts`, `coach_invites`, `password_reset_tokens`, `in_person_payment_tokens`, `schools`

### Key Models

- **User:** username, email, password_hash, role (player/coach), is_admin, subscription_tier, stripe IDs
- **PlayerProfile:** name, position, year, physical stats (height/weight/forty/bench/vertical/squat/clean/broad_jump/pro_agility/wingspan), GPA, school/city/state, bio, social links, offers, visits, stars (0-5)
- **CoachProfile:** name, school, title, division, conference

## File Structure

```
/home/recruiting/bearcats/
├── main.py                 # Entire application
├── recruiting.db           # SQLite database
├── .env                    # Environment variables (secrets)
├── templates/              # Jinja2 templates (24 files)
│   ├── base.html           # Layout with nav bar
│   ├── dashboard.html      # Player browsing
│   ├── profile.html        # Player profile view
│   ├── edit_profile.html   # Profile editor
│   ├── questionnaires.html # Recruiting questionnaire links (premium)
│   └── ...
├── static/
│   ├── style.css           # All styles
│   ├── cap-logo.png        # Logo
│   ├── uploads/            # Profile photos (local)
│   └── docs/               # Legal PDFs
├── signed_docs/            # Signed legal contracts
├── venv/                   # Python virtual environment
├── expire_in_person.py     # Cron: expire bypass memberships
├── populate_schools.py     # Populate schools table
├── git_autopush.sh         # Auto-commit & push every 30min
└── test_*.py               # Test files
```

## Server Infrastructure

- **IP:** 167.71.170.219 (DigitalOcean)
- **Nginx:** `/etc/nginx/sites-available/caprecruiting` — rate limiting, WebSocket proxy, 4GB upload limit
- **systemd:** `/etc/systemd/system/bearcats.service` — auto-restart, runs as `bearcats` user on port 8080
- **Cron (root):** git_autopush every 30min, expire_in_person daily at 9am UTC
- **Git:** `git@github-bearcats:divinedavis/CAPRecruiting.git` (SSH alias in `/root/.ssh/config`)

## Deployment

After making changes to files on the server:
1. `systemctl restart bearcats` to apply changes
2. Commit and push: `cd /home/recruiting/bearcats && git add -A && git commit -m "message" && git push origin main`

## Important Patterns

- **CSRF:** Custom middleware checks origin/referer on non-safe methods; `/stripe/webhook` is exempt
- **Sessions:** Starlette SessionMiddleware stores `user_id`, `is_admin`, `role`, `subscription_tier`
- **WebSocket:** Real-time unread message badge updates on all pages
- **All paths are hardcoded** to `/home/recruiting/bearcats/` (DB, static, templates, uploads, signed_docs)
- **Email subjects/from** use "CAP Recruiting" branding (except a few legacy "Bearcats" references in password reset)
