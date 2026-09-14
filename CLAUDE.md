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

`users`, `player_profiles`, `coach_profiles`, `teams`, `videos`, `photos`, `profile_images`, `transcripts`, `evaluations`, `messages`, `legal_contracts`, `coach_invites`, `password_reset_tokens`, `in_person_payment_tokens`, `comp_invites`, `schools`

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
  - Live copy is `sites-enabled/caprecruiting`; both it and `conf.d/rate_limits.conf`
    are mirrored in `deploy/nginx/` in this repo. Edit the repo copy and the live
    file together, then `nginx -t && systemctl reload nginx`.
- **`/static/` is served by nginx off disk, not by the app.** Files need to be
  world-readable (644) and their directories world-traversable (755);
  `/home/recruiting/bearcats` is 751 so www-data can traverse to `static/` without
  being able to list the app dir or read `.env` (600) or `recruiting.db` (640).
  Two carve-outs: `static/uploads/` (mode 750, user-uploaded profile photos) still
  proxies to uvicorn's StaticFiles mount, and `*.bak*`/`*.orig`/`*.old` under
  `/static/` are denied.
  - Cache headers come from nginx: 30d on images, 1h on css/js (not every code
    reference is cache-busted). Adding an `add_header` inside a `/static/` block
    would silently drop the inherited server-level security headers — use
    `expires` instead.
- **Static bursts have their own rate-limit zone (`cap_static`).** The homepage
  marquee is ~150 requests in one page load; on `cap_general` it 429'd and
  fail2ban banned the visitor for 24h (fixed 2026-09-12). Any new page that fans
  out to many assets belongs in `cap_static`, never `cap_general`.
- **systemd:** `/etc/systemd/system/bearcats.service` — auto-restart, runs as `bearcats` user on port 8080
- **Cron (root):** git_autopush every 30min, expire_in_person daily at 9am UTC
- **Git:** `git@github-bearcats:divinedavis/CAPRecruiting.git` (SSH alias in `/root/.ssh/config`)

## Route Map

### Public (no login required)

| Route | Description |
|-------|-------------|
| `GET /` | Landing page (`home.html`) |
| `GET /pricing` | Plan selection page (`pricing.html`) |
| `GET /signup` | Signup form; accepts `tier`, `billing`, `invite`, `bypass_token`, `comp` query params (`signup.html`) |
| `POST /signup` | Creates user+profile, handles coach invites, bypass tokens, comped links, Stripe checkout redirect |
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
| `POST /admin/comp-links/generate` | Generate a free (comped) profile link for a new player — tier, expiry, note |
| `POST /admin/comp-links/{token}/revoke` | Revoke an unclaimed comped link |

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

### Free Profile Links (Comped)
`POST /admin/comp-links/generate` on `/admin/invites` — admin picks a tier
(essentials / advanced / premium), a link expiry (7/30/90 days) and an optional
note, and gets `https://caprecruiting.com/signup?comp={token}` to text the
player. The player signs up on that tier with no payment screen. Uses the
`CompInvite` model, single use, revocable via `/admin/comp-links/{token}/revoke`.

**Not the same as a bypass link.** A bypass link stamps `in_person_paid_until`,
so `expire_in_person.py` drops the player to free on that date. A comped profile
sets no end date and no Stripe subscription, so nothing downgrades it — the
*link* expires, the granted tier does not.

The tier is read from the invite row, never from the posted form, so a player
can't edit `tier` in the HTML and comp themselves Premium. The token is burned
with a conditional `UPDATE ... WHERE used_at IS NULL` before the user row is
created, so a forwarded link can't be redeemed twice.

Works through Google and Apple sign-in too: `/auth/google?comp=` stashes the
token in the session, `/auth/apple?comp=` puts it in the signed state blob, and
both callbacks copy it onto `pending_signups.comp_token` (the callbacks clear
the session, so the token has to ride on the row). `/signup/finish-oauth` then
redeems it and skips Stripe entirely.

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

**REQUIRED after EVERY change:** You must always (1) restart the service, (2) test ALL endpoints, and (3) commit + push to GitHub. Never skip any of these steps.

1. `systemctl restart bearcats` to apply changes
2. Run the full endpoint test suite below — if ANY endpoint returns `500`, fix before proceeding
3. Commit and push: `cd /home/recruiting/bearcats && git add -A && git commit -m "message" && git push origin main`

## Error Alerting

Anything that fails anywhere on the platform emails the operator (`ALERT_EMAIL` in
`.env`) within seconds of it happening.

- **`error_alerts.py`** — the watcher, running as `cap-error-alerts.service`
  (unit tracked in the repo at `deploy/cap-error-alerts.service`).
- **Watches:** journald for the `bearcats` and `nginx` units,
  `/var/log/nginx/bearcats-error.log`, the cron job logs, plus an active health
  probe of the public URL and `127.0.0.1:8080` every 60s.
- **Alerts on:** unhandled exceptions (full traceback, request path, user id, IP),
  any 5xx or 413 response, every `_logger.error`/`_logger.exception` record,
  systemd crashes / restarts / OOM kills, nginx `[error]` and worse, failures in
  the cron jobs, and site-down / site-recovered.
- **Stays quiet about:** 404s, bot probes, 403s, and WARNING records (counted and
  reported in the weekly summary instead). nginx `cap_*` rate-limit blocks are
  counted separately from application errors; a client hitting the same zone
  5x in 10 minutes triggers a warning alert, subject to email deduplication.
- **Noise control:** an identical error is collapsed for 15 minutes and then
  re-sent with a repeat count; hard cap of 12 emails/hour with the overflow
  delivered as a single digest. Stripe keys, tokens, passwords and session
  cookies are masked before anything is mailed.
- **Proof of life:** a summary email every Monday 9am ET (root crontab,
  `error_alerts.py --heartbeat`) so silence can be trusted.
- **Weekly accounting:** timestamped events retained for seven days, independent
  of lifetime dedupe counts and SMTP delivery. The report states its actual
  coverage window, labels partial coverage after upgrade or the 50,000-event
  retention cap, and lists rate-limit blocks separately. A response recorded by
  both app middleware and the access log is counted once. Retrying a heartbeat
  does not reset history. Legacy state and the old baseline can remain in place.
- **Offline regressions:** `python -m unittest test_alerts_regression
  test_auth_upload_regression` in the app virtualenv. These use temporary state
  and databases, simulated Google responses, and in-memory storage; no mail is
  sent. Google account selection/consent also needs a real browser check.

**Every new failure path must stay visible.** Do not write `except Exception: pass` —
use `_logger.exception("what failed and for whom")` so it turns into an email. The
root logging handler configured at the top of `main.py` is what stamps the level
onto the record; the watcher keys off that.

### Testing the alert chain

```bash
# SMTP + formatting only
cd /home/recruiting/bearcats && set -a && . ./.env && set +a && ./venv/bin/python3 error_alerts.py --test

# a real exception through the real path (token is in .env)
TOK=$(grep ^ERROR_TEST_TOKEN= .env | cut -d= -f2)
curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8080/__selftest/error?token=$TOK"
journalctl -u cap-error-alerts -n 20 --no-pager   # expect one "emailed: ..." line
```

Repeats inside 15 minutes are suppressed by design — `rm /var/lib/cap-error-alerts/state.json`
and restart the service when re-testing the same error.

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

## Pre-Push Security Check

Before every git commit/push, scan staged files for secrets:
```bash
git diff --cached | grep -iE "(sk_live|sk_test|pk_live|pk_test|gho_|ghp_|AKIA|secret_key|password|smtp_pass|whsec_|SPACES_SECRET|session_secret)"
```
If ANY match is found, **do NOT commit**. Remove the secret from the file, add it to `.env` instead, and make sure `.env` is in `.gitignore`.

Never commit files containing API keys, tokens, passwords, or credentials. All secrets must live in `.env` and be loaded at runtime.

### Verify EVERY feature actually works (not just HTTP codes)

A `200`/`302` only proves the route renders — it does NOT prove the feature works. After **every** change, confirm the actual functionality end-to-end, including (at minimum):

- **Videos** — upload plays in-browser (watch the HEVC/codec gotcha), pin/delete work, CDN URL loads.
- **Photos** — profile photo + gallery upload, display, and delete work; images actually render (not broken links).
- **Links** — every external/social link (Hudl, X, Instagram, news links, custom links) opens and points to the right URL; internal nav links and buttons all work.
- **Every other feature touched or nearby** — messaging send/receive, commitment school + logo, offers, visits, stats, questionnaire, payments/upgrade, admin tools (mass DM, edit profile, invites).

Prefer a real authenticated walkthrough (log in as a test player/coach/admin and click through) or set real data in the DB and confirm the rendered HTML contains it. Never assume a green status code means the feature works. If anything is broken, fix it before committing.
