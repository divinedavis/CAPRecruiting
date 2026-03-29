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
├── templates/              # Jinja2 templates (25 files)
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
│   └── docs/               # Legal PDFs, cap_agreement.pdf template
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

## Route Map

### Public (no login required)

| Route | Description |
|-------|-------------|
| `GET /` | Landing page (`home.html`) |
| `GET /pricing` | Plan selection page (`pricing.html`) |
| `GET /signup` | Signup form; accepts `tier`, `billing`, `invite`, `bypass_token` query params (`signup.html`) |
| `POST /signup` | Creates user+profile, handles coach invites, bypass tokens, Stripe checkout redirect |
| `GET /login` | Login form (`login.html`) |
| `POST /login` | Authenticates user, sets session (`user_id`, `is_admin`, `role`, `subscription_tier`) |
| `GET /logout` | Clears session, redirects to `/` |
| `GET /dashboard` | Player directory with school/year/position filters (`dashboard.html`) |
| `GET /profile/{username}` | View player/coach profile; tier-gates photos, offers, visits, videos, contact (`profile.html`) |
| `GET /videos/{username}` | Full video list for a player (`videos.html`) |
| `GET /forgot-password` | Password reset request form (`forgot_password.html`) |
| `POST /forgot-password` | Sends password reset email |
| `GET /reset-password/{token}` | Reset form with token validation (`reset_password.html`) |
| `POST /reset-password/{token}` | Updates password hash |
| `GET /sign/{token}` | Legal contract signing page (`sign.html` or `sign_done.html`) |
| `POST /sign/{token}` | Processes signature, overlays on PDF template, saves signed PDF |

### Authenticated (login required)

| Route | Description |
|-------|-------------|
| `GET /profile/edit` | Edit own profile (`edit_profile.html`) |
| `POST /profile/edit` | Save profile fields |
| `POST /profile/upload-photo` | Upload main profile photo to local disk |
| `POST /profile/images/upload` | Upload gallery image to DO Spaces (resizes to 1200px JPEG, max 20) |
| `POST /profile/images/{id}/pin` | Toggle pin on gallery image (max 5 pinned) |
| `POST /profile/images/{id}/delete` | Delete gallery image from S3 and DB |
| `POST /profile/videos/upload` | Upload video to DO Spaces (validates magic bytes, max 4GB) |
| `POST /profile/videos/{id}/pin` | Toggle pin on video (only one pinned at a time) |
| `POST /profile/videos/{id}/delete` | Delete video from S3 and DB |
| `POST /profile/transcripts/upload` | Upload transcript (PDF/DOC/DOCX) to S3 (max 4, max 10MB) |
| `POST /profile/transcripts/{id}/delete` | Delete transcript from S3 and DB |
| `GET /profile/transcripts/{id}/download` | Download transcript; tier-gated (advanced+) for coaches |
| `GET /profile/transcripts/{id}/view` | Transcript viewer page |
| `POST /profile/{username}/evaluate` | Coach/admin submits text evaluation for a player (max 5000 chars) |
| `GET /questionnaires` | Premium-only football questionnaire links (`questionnaires.html`) |

### Messaging (login required)

| Route | Description |
|-------|-------------|
| `GET /messages` | Inbox with conversation list and unread counts (`messages.html`) |
| `GET /messages/{username}` | Conversation thread; marks unread as read (`conversation.html`) |
| `POST /messages/{username}` | Send message via form POST; pushes via WebSocket |
| `POST /messages/{username}/send` | Send message via AJAX/JSON |
| `POST /messages/{username}/delete-thread` | Soft-delete conversation for current user |
| `POST /messages/delete-conversations` | Bulk soft-delete multiple threads |
| `WebSocket /ws/{user_id}` | Real-time message delivery and unread badge updates |

### Subscription / Upgrade

| Route | Description |
|-------|-------------|
| `GET /upgrade` | Upgrade options page with current tier display (`upgrade.html`) |
| `POST /upgrade/checkout` | Creates Stripe Checkout Session (or redirects to billing portal if already subscribed) |
| `GET /upgrade/success` | Post-checkout success; refreshes session tier (`upgrade_success.html`) |
| `POST /upgrade/manage` | Redirects to Stripe Customer Portal |
| `POST /stripe/webhook` | Handles Stripe events (see Stripe Webhook Lifecycle below) |
| `GET /join/{token}` | Bypass payment landing page (`join.html`) |
| `POST /join/{token}` | Activates bypass: sets premium tier + in_person_paid_until |

### Admin (admin-only)

| Route | Description |
|-------|-------------|
| `POST /admin/users/{id}/set-stars` | Set player star rating (0-5) |
| `POST /admin/users/{id}/set-tier` | Override subscription tier directly |
| `GET /admin/teams` | Team list with player counts and coaches (`admin_teams.html`) |
| `POST /admin/teams/create` | Create new team |
| `GET /admin/users/{id}/edit-profile` | Edit any user's profile (reuses `edit_profile.html`) |
| `POST /admin/users/{id}/edit-profile` | Save edits for any user |
| `GET /admin/invites` | List all coach invite tokens (`admin_invites.html`) |
| `POST /admin/invites/create` | Create coach invite (UUID token, 7-day expiry, optional note) |
| `POST /admin/invites/{token}/revoke` | Expire invite immediately |
| `POST /admin/users/{id}/delete` | Hard-delete user and all related data (see caveat below) |
| `POST /admin/users/{id}/generate-bypass` | Generate bypass link for existing player (7-day expiry) |
| `POST /admin/bypass-links/generate` | Generate open bypass link for new signups |

### Legal (admin-only)

| Route | Description |
|-------|-------------|
| `GET /legal` | List all non-hidden contracts (`legal.html`) |
| `POST /legal/create` | Create contract with player_name and signing token |
| `POST /legal/{id}/hide` | Soft-hide a contract |
| `GET /legal/docs/{filename}` | Serve signed PDF (path traversal protected) |

### API (JSON)

| Route | Description |
|-------|-------------|
| `GET /api/schools/states` | Distinct states from schools table |
| `GET /api/schools/cities?state=X` | Cities for a state |
| `GET /api/schools/list?state=X&city=Y` | School names for state+city |

## Template-to-Route Mapping

| Template | Rendered by |
|----------|-------------|
| `home.html` | `GET /` |
| `pricing.html` | `GET /pricing` |
| `signup.html` | `GET /signup`, `POST /signup` (on error) |
| `login.html` | `GET /login`, `POST /login` (on error) |
| `forgot_password.html` | `GET /forgot-password` |
| `reset_password.html` | `GET /reset-password/{token}` |
| `dashboard.html` | `GET /dashboard` |
| `edit_profile.html` | `GET /profile/edit`, `GET /admin/users/{id}/edit-profile` |
| `profile.html` | `GET /profile/{username}` |
| `videos.html` | `GET /videos/{username}` |
| `messages.html` | `GET /messages` |
| `conversation.html` | `GET /messages/{username}` |
| `questionnaires.html` | `GET /questionnaires` |
| `upgrade.html` | `GET /upgrade` |
| `upgrade_success.html` | `GET /upgrade/success` |
| `join.html` | `GET /join/{token}` |
| `sign.html` | `GET /sign/{token}` (unsigned) |
| `sign_done.html` | `GET /sign/{token}` (signed), `POST /sign/{token}` |
| `legal.html` | `GET /legal` |
| `admin_teams.html` | `GET /admin/teams` |
| `admin_invites.html` | `GET /admin/invites` |

## Admin Workflows

### Bypass Links (In-Person Payment)
Two types, both use `InPersonPaymentToken`:
1. **User-specific** (`/admin/users/{id}/generate-bypass`): Token tied to existing player. Player visits `/join/{token}` and confirms to get premium + `in_person_paid_until = 2027-03-26`.
2. **Open** (`/admin/bypass-links/generate`): Token with `user_id=None`. Redirects to `/signup?bypass_token={token}` for new signups. Signup flow sets premium automatically.

Both expire in 7 days. The `expire_in_person.py` cron (daily 9am UTC) checks for expired `in_person_paid_until` dates, emails a renewal notice, and downgrades to free.

### Star Ratings
`POST /admin/users/{id}/set-stars` — sets `PlayerProfile.stars` (0-5, clamped). Displayed on player profiles.

### Tier Overrides
`POST /admin/users/{id}/set-tier` — directly sets `User.subscription_tier`. Does NOT update the user's session, so the user won't see the change until they log in again.

### Coach Invites
- Create: generates UUID token, 7-day expiry, optional note
- Coaches register at `/signup?invite={token}`
- Revoke: sets `expires_at` to now

### User Deletion
`POST /admin/users/{id}/delete` — hard-deletes user + PlayerProfile, CoachProfile, Messages, Videos, Transcripts, Evaluations.
**Caveats:** Does NOT delete files from DO Spaces (orphaned), does NOT delete local profile photos from `/static/uploads/`, does NOT cancel Stripe subscriptions. Cannot self-delete.

## Stripe Webhook Lifecycle

`POST /stripe/webhook` handles 4 event types:

| Event | Action |
|-------|--------|
| `checkout.session.completed` | Sets user tier + subscription ID from metadata |
| `customer.subscription.updated` | If `active`: updates tier. If `canceled`/`unpaid`/`past_due`: downgrades to free |
| `customer.subscription.deleted` | Downgrades to free, clears subscription ID |
| `invoice.payment_failed` | Downgrades to free (looks up user by `stripe_customer_id`, not metadata) |

Webhook does NOT update user sessions — tier change visible on next login.

## Known Gotchas

### Session Staleness
`subscription_tier` in the session can go stale if changed by:
- Admin tier override (`set-tier`)
- Stripe webhook (subscription changes)
- `expire_in_person.py` cron (downgrades expired bypass users)

Session tier is only refreshed at: login, signup, upgrade success, `/questionnaires`, and `/join/{token}`. Any nav bar or template check using `session["subscription_tier"]` may show stale info until refresh.

### Hardcoded Paths
9 occurrences of `/home/recruiting/bearcats/` in main.py: DB path, static mount, templates dir, upload dir, signed docs dir, PDF template, and 3 direct `sqlite3.connect()` calls in the school API endpoints.

### School API Bypasses SQLAlchemy
The 3 `/api/schools/*` endpoints use raw `sqlite3.connect()` instead of SQLAlchemy. They open/close their own connections.

### Player-to-Player Messaging
Players cannot message other players — only coach-to-player and player-to-coach messaging is allowed.

## Important Patterns

- **CSRF:** Custom middleware checks origin/referer on non-safe methods; `/stripe/webhook` is exempt
- **Sessions:** Starlette SessionMiddleware stores `user_id`, `is_admin`, `role`, `subscription_tier`
- **WebSocket:** Real-time unread message badge updates on all pages
- **File validation:** Videos and transcripts validated by magic bytes, not just extension
- **Image processing:** Gallery images resized to 1200px width, converted to JPEG before S3 upload
- **Email subjects/from** use "CAP Recruiting" branding (except a few legacy "Bearcats" references in password reset)

## Deployment

After making changes to files on the server:
1. `systemctl restart bearcats` to apply changes
2. Commit and push: `cd /home/recruiting/bearcats && git add -A && git commit -m "message" && git push origin main`

## Post-Change Testing (REQUIRED)

After every change, restart the service and test ALL key endpoints to verify nothing is broken:

```bash
systemctl restart bearcats && sleep 2

# Check service is running
systemctl status bearcats | head -5

# Public pages
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/pricing
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/login
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/signup
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/dashboard
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/forgot-password

# API endpoints
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/api/schools/states
curl -s -o /dev/null -w '%{http_code}' 'https://caprecruiting.com/api/schools/cities?state=PA'
curl -s -o /dev/null -w '%{http_code}' 'https://caprecruiting.com/api/schools/list?state=PA&city=Pittsburgh'

# Auth-required pages (should return 302 redirect to /login)
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/profile/edit
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/messages
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/upgrade
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/questionnaires
curl -s -o /dev/null -w '%{http_code}' https://caprecruiting.com/legal

# Stripe webhook endpoint (should return 400, not 500 — means route is reachable)
curl -s -o /dev/null -w '%{http_code}' -X POST https://caprecruiting.com/stripe/webhook
```

**Expected results:**
- Public pages: `200`
- Auth-required pages: `302` (redirect to login) or `200` if testing logged in
- API endpoints: `200` with JSON
- Stripe webhook: `400` (bad request, no payload) — NOT `500`
- If ANY endpoint returns `500`, investigate immediately before committing

**Quick smoke test (one-liner):**
```bash
for url in / /pricing /login /signup /dashboard /forgot-password /api/schools/states /profile/edit /messages /upgrade /questionnaires; do echo -n "$url "; curl -s -o /dev/null -w '%{http_code}\n' "https://caprecruiting.com$url"; done
```
