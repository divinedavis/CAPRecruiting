#!/usr/bin/env python3
"""
CAP Recruiting error alerter.

Watches every place the platform can fail and emails a human-readable alert the
moment something breaks:

  * journald for the `bearcats` and `nginx` units  — unhandled exceptions,
    tracebacks, ERROR/CRITICAL log records, HTTP 5xx responses, service crashes
    and restarts, OOM kills.
  * /var/log/nginx/bearcats-error.log             — upstream timeouts, 502/504,
    TLS failures, request-body limits.
  * the cron job logs                             — nightly expiry, monthly
    payments report, weekly dep check + S3 backup.
  * an active health probe                        — public HTTPS URL and the
    local uvicorn port, so a total outage (which logs nothing at all) still
    alerts.

Noise control: identical failures are collapsed by signature, repeats inside a
15-minute window are counted rather than re-sent, and there is a hard cap on
emails per hour with the overflow delivered as one digest. A single trip of the
nginx `cap_auth` rate limit (a crawler bursting /signup) is not worth an email;
that zone alerts only when one client keeps tripping it. A refused upstream
while bearcats is restarting (unattended upgrades, the nightly auto-reboot) is
dropped too — the health probe still catches a real outage. Secrets that show up
in tracebacks (Stripe keys, session cookies, passwords) are masked before the
mail goes out.

Run modes:
  error_alerts.py                 daemon (systemd: cap-error-alerts.service)
  error_alerts.py --test          send one sample alert, verifies SMTP end-to-end
  error_alerts.py --heartbeat     weekly "still watching" summary email
"""

import html
import json
import os
import queue
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from collections import Counter
from datetime import datetime, timedelta
from email.message import EmailMessage

APP_DIR = "/home/recruiting/bearcats"
STATE_DIR = "/var/lib/cap-error-alerts"
STATE_PATH = os.path.join(STATE_DIR, "state.json")

ALERT_TO = os.environ.get("ALERT_EMAIL", "divinejdavis@gmail.com")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "support@caprecruiting.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SITE_URL = os.environ.get("SITE_URL", "https://caprecruiting.com")
LOCAL_URL = "http://127.0.0.1:8080/"

JOURNAL_UNITS = ["bearcats", "nginx"]
FILE_SOURCES = [
    ("nginx", "/var/log/nginx/bearcats-error.log"),
    ("cron:expire-in-person", "/var/log/cap_expire_in_person.log"),
    ("cron:payments-report", "/var/log/cap_payments_report.log"),
    ("cron:git-autopush", "/home/recruiting/bearcats/git_autopush.log"),
]

SUPPRESS_WINDOW = 900        # seconds a repeat of the same signature stays quiet
MAX_EMAILS_PER_HOUR = 12     # overflow is batched into a single digest
HEALTH_INTERVAL = 60         # seconds between health probes
HEALTH_FAILURES_TO_ALERT = 3 # consecutive probe failures before "site down"
TB_IDLE_FLUSH = 1.5          # a traceback is complete after this long with no new lines
ASGI_DUP_WINDOW = 10         # uvicorn re-logs what our middleware already reported
ACCESS_HOLD = 3              # wait this long before mailing a bare 5xx access line
AUTH_LIMIT_TRIPS = 5         # cap_auth rate-limit hits from one client before alerting
AUTH_LIMIT_WINDOW = 600      # ...within this many seconds (one crawler burst = 1 trip)
DENY_TRIPS = 10              # deny-rule 403s from one client before alerting
DENY_WINDOW = 600            # ...within this many seconds (a drive-by .bak probe = 1 trip)

# ── What counts as an error ───────────────────────────────────────────────────

# uvicorn access line: INFO:     1.2.3.4:0 - "GET /path HTTP/1.1" 200 OK
ACCESS_RE = re.compile(r'^INFO:\s+(\S+) - "(\w+) (\S+) HTTP/[\d.]+" (\d{3})')
# our own logging format: 2026-08-15 12:00:00,000 ERROR bearcats: message
LEVEL_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d[,\d]* (ERROR|CRITICAL|WARNING) ")

HARD_ERROR_PATTERNS = [
    "Traceback (most recent call last)",
    "Exception in ASGI application",
    "ERROR:",
    "CRITICAL:",
    "sqlalchemy.exc.",
    "sqlite3.OperationalError",
    "database is locked",
    "No space left on device",
    "MemoryError",
    "botocore.exceptions",
    "stripe.error",
    "SMTPException",
    "send failed",
    "[APP-ERROR]",
]

# systemd lifecycle events worth an email
SERVICE_PATTERNS = [
    ("Main process exited", "service process exited"),
    ("Failed to start", "service failed to start"),
    ("Scheduled restart job", "service restarting"),
    ("core-dump", "service core dumped"),
    ("Killed process", "process killed (out of memory)"),
    ("Out of memory", "out of memory"),
    ("Failed with result", "service failed"),
    ("start request repeated too quickly", "service crash-looping"),
]

# never alert on these — normal operation or unavoidable internet background noise
IGNORE_PATTERNS = [
    "Unsupported upgrade request",
    "client closed connection",
    "SSL_do_handshake() failed",
    "no such file or directory) while reading upstream",  # client aborted download
    "Deactivated successfully",
    "Consumed ",
    "Started bearcats.service",
    "Stopping bearcats.service",
    "Stopped bearcats.service",
]

NGINX_LEVEL_RE = re.compile(r"\[(error|crit|alert|emerg)\]")
LIMIT_REQ_RE = re.compile(r'limiting requests, .*?by zone "(\w+)", client: ([\w.:]+)')
DENY_RE = re.compile(r'access forbidden by rule, client: ([\w.:]+)')

# The routes that actually take a file. Everything else that 413s hit the
# blanket body cap instead, and calling that "upload rejected" sent us looking
# for a broken upload form when the request was a POST to /login. Keep in step
# with _BodySizeLimitMiddleware._UPLOAD_PATHS / _UPLOAD_RE in main.py.
# Prefix match for the path set and an exact match for the card image, the same
# way main.py splits them between _UPLOAD_PATHS (startswith) and _UPLOAD_RE.
UPLOAD_PATH_RE = re.compile(
    r"^/(?:profile/(?:upload-photo|upload-committed-logo|videos/upload"
    r"|images/upload|transcripts/upload)|sign/)"
    r"|^/dashboard/scout/card/[^/]+/image$")

# cron/script logs: only these shapes are errors
FILE_ERROR_PATTERNS = [
    "Traceback (most recent call last)",
    "Error:", "ERROR", "error:", "Exception", "failed", "FAILED", "fatal",
]

# ── Secret masking ────────────────────────────────────────────────────────────

REDACTIONS = [
    (re.compile(r"\b(sk_live|sk_test|rk_live|pk_live|whsec)_[A-Za-z0-9]+"), r"\1_***REDACTED***"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+"),
     r"\1=***REDACTED***"),
    (re.compile(r"(?i)(session|csrftoken)=[A-Za-z0-9._\-]+"), r"\1=***REDACTED***"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-]+"), "Bearer ***REDACTED***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "***PRIVATE KEY REDACTED***"),
]


def redact(text: str) -> str:
    for pattern, repl in REDACTIONS:
        text = pattern.sub(repl, text)
    if SMTP_PASSWORD:
        text = text.replace(SMTP_PASSWORD, "***REDACTED***")
    for key in ("SPACES_SECRET", "SESSION_SECRET", "STRIPE_SECRET_KEY",
                "STRIPE_WEBHOOK_SECRET", "GOOGLE_CLIENT_SECRET"):
        val = os.environ.get(key, "")
        if val and len(val) > 8:
            text = text.replace(val, f"***{key}***")
    return text


# ── Event signature (dedupe key) ──────────────────────────────────────────────

SIG_SCRUB = [
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-f]{8,}\b", re.I), "<hex>"),
    (re.compile(r"\b\d+\b"), "<n>"),
    (re.compile(r"'[^']{0,80}'"), "'<v>'"),
]


def signature(source: str, text: str) -> str:
    head = text.strip().split("\n")
    # for a traceback the last line (the exception type) identifies it best
    key = head[-1] if len(head) > 1 else head[0]
    if len(head) > 1:
        key = f"{head[0][:80]} :: {key}"
    for pattern, repl in SIG_SCRUB:
        key = pattern.sub(repl, key)
    return f"{source}|{key[:220]}"


# ── State ─────────────────────────────────────────────────────────────────────

class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.seen = {}          # signature -> {"last": ts, "count": n, "first": ts}
        self.email_times = []   # timestamps of sent emails (rolling hour)
        self.digest = []        # suppressed-by-rate-limit events
        self.counters = Counter()
        self.load()

    def load(self):
        try:
            with open(STATE_PATH) as fh:
                data = json.load(fh)
            self.seen = data.get("seen", {})
            self.email_times = data.get("email_times", [])
            self.counters = Counter(data.get("counters", {}))
        except Exception:
            pass

    def save(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            tmp = STATE_PATH + ".tmp"
            with open(tmp, "w") as fh:
                json.dump({
                    "seen": self.seen,
                    "email_times": self.email_times,
                    "counters": dict(self.counters),
                    "saved_at": time.time(),
                }, fh)
            os.replace(tmp, STATE_PATH)
        except Exception as exc:
            log(f"state save failed: {exc}")


def log(msg: str):
    print(f"[error-alerts] {msg}", flush=True)


# ── Email ─────────────────────────────────────────────────────────────────────

def send_email(subject: str, body_text: str, body_html: str) -> bool:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"CAP Recruiting Alerts <{SMTP_USER}>"
    msg["To"] = ALERT_TO
    msg.set_content(body_text)
    msg.add_alternative(body_html, subtype="html")
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls(context=ctx)
            if SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        log(f"EMAIL SEND FAILED: {exc}")
        return False


def render(event: dict) -> tuple:
    when = datetime.fromtimestamp(event["ts"]).strftime("%b %d, %Y at %-I:%M:%S %p")
    detail = redact(event["text"]).strip()
    repeat = ""
    if event.get("count", 1) > 1:
        repeat = f"\nSeen {event['count']} times since " \
                 f"{datetime.fromtimestamp(event['first']).strftime('%-I:%M %p')}."

    text = (
        f"{event['title']}\n\n"
        f"When:   {when}\n"
        f"Source: {event['source']}\n"
        f"Site:   {SITE_URL}{repeat}\n\n"
        f"{'-' * 60}\n{detail}\n{'-' * 60}\n\n"
        f"Live logs:  ssh root@167.71.170.219 "
        f"'journalctl -u bearcats -n 200 --no-pager'\n"
    )

    color = "#dc2626" if event.get("severity", "error") == "error" else "#d97706"
    html_body = f"""\
<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:680px;margin:0 auto;">
  <div style="border-left:4px solid {color};padding:12px 16px;background:#fef2f2;">
    <div style="font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:{color};font-weight:700;">
      CAP Recruiting &middot; {html.escape(event['source'])}
    </div>
    <div style="font-size:18px;font-weight:700;color:#111827;margin-top:4px;">
      {html.escape(event['title'])}
    </div>
  </div>
  <table style="margin:16px 0;font-size:14px;color:#374151;border-collapse:collapse;">
    <tr><td style="padding:2px 12px 2px 0;color:#6b7280;">When</td><td>{html.escape(when)}</td></tr>
    <tr><td style="padding:2px 12px 2px 0;color:#6b7280;">Site</td>
        <td><a href="{SITE_URL}" style="color:#2563eb;">{html.escape(SITE_URL)}</a></td></tr>
    {f'<tr><td style="padding:2px 12px 2px 0;color:#6b7280;">Repeats</td><td>{event["count"]} times</td></tr>'
      if event.get('count', 1) > 1 else ''}
  </table>
  <pre style="background:#0f172a;color:#e2e8f0;padding:14px;border-radius:6px;overflow-x:auto;
              font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;">{html.escape(detail)}</pre>
  <p style="font-size:12px;color:#6b7280;margin-top:16px;">
    Automated by <code>cap-error-alerts</code> on 167.71.170.219 &middot;
    repeats of the same error are collapsed for 15 minutes.
  </p>
</div>"""
    return text, html_body


# ── Dispatcher ────────────────────────────────────────────────────────────────

class Dispatcher(threading.Thread):
    def __init__(self, state: State, events: queue.Queue):
        super().__init__(daemon=True)
        self.state = state
        self.events = events

    def run(self):
        while True:
            try:
                event = self.events.get(timeout=30)
            except queue.Empty:
                self.flush_digest()
                continue
            try:
                self.handle(event)
            except Exception as exc:
                log(f"dispatch error: {exc}")

    def handle(self, event: dict):
        now = time.time()
        sig = event["signature"]
        with self.state.lock:
            self.state.counters[event.get("severity", "error")] += 1
            rec = self.state.seen.get(sig)
            if rec and now - rec["last"] < SUPPRESS_WINDOW:
                rec["count"] += 1
                rec["last"] = now
                self.state.save()
                return                      # already told them, stay quiet
            first = rec["first"] if rec else now
            count = (rec["count"] + 1) if rec else 1
            self.state.seen[sig] = {"last": now, "count": count, "first": first}
            # prune old signatures
            for k in [k for k, v in self.state.seen.items() if now - v["last"] > 7 * 86400]:
                del self.state.seen[k]

            self.state.email_times = [t for t in self.state.email_times if now - t < 3600]
            over_cap = len(self.state.email_times) >= MAX_EMAILS_PER_HOUR
            if not over_cap:
                self.state.email_times.append(now)
            else:
                self.state.digest.append(event)
            self.state.save()

        if over_cap:
            log(f"rate-limited, digesting: {event['title']}")
            return

        event["count"] = count
        event["first"] = first
        text, html_body = render(event)
        subject = f"[CAP ALERT] {event['title']}"[:180]
        if send_email(subject, text, html_body):
            log(f"emailed: {event['title']}")

    def flush_digest(self):
        with self.state.lock:
            pending = self.state.digest
            if not pending:
                return
            now = time.time()
            self.state.email_times = [t for t in self.state.email_times if now - t < 3600]
            if len(self.state.email_times) >= MAX_EMAILS_PER_HOUR:
                return                       # still capped, keep holding
            self.state.digest = []
            self.state.email_times.append(now)
            self.state.save()

        groups = Counter(e["title"] for e in pending)
        lines = [f"{n:>4}x  {title}" for title, n in groups.most_common()]
        text = ("Errors held back by the rate limit "
                f"({len(pending)} total):\n\n" + "\n".join(lines))
        html_body = ("<div style=\"font-family:-apple-system,sans-serif\">"
                     "<h2 style='color:#dc2626'>CAP Recruiting — error burst digest</h2>"
                     f"<p>{len(pending)} further errors while rate-limited:</p><ul>"
                     + "".join(f"<li><b>{n}x</b> {html.escape(t)}</li>"
                               for t, n in groups.most_common())
                     + "</ul></div>")
        send_email(f"[CAP ALERT] {len(pending)} more errors (digest)", text, html_body)


# ── Sources ───────────────────────────────────────────────────────────────────

def emit(events: queue.Queue, source: str, title: str, text: str, severity="error"):
    title = redact(title)
    events.put({
        "ts": time.time(),
        "source": source,
        "title": title[:150],
        "text": text,
        "severity": severity,
        "signature": signature(source, title + "\n" + text),
    })


def classify_app_line(line: str):
    """Return (title, severity) for a bearcats journal line, or None to ignore."""
    if any(p in line for p in IGNORE_PATTERNS):
        return None

    access = ACCESS_RE.match(line)
    if access:
        _ip, method, path, status = access.groups()
        code = int(status)
        if code >= 500:
            return (f"HTTP {code} on {method} {path}", "error")
        if code == 413:
            if UPLOAD_PATH_RE.match(path.split("?", 1)[0]):
                return (f"Upload rejected — too large: {method} {path}", "error")
            return (f"Request body too large: {method} {path}", "error")
        return None

    level = LEVEL_RE.match(line)
    if level:
        lvl = level.group(1)
        msg = line.split(": ", 1)[-1].strip()
        if lvl == "WARNING":
            return None                      # counted, reported in the heartbeat
        return (msg[:150] or f"{lvl} log record", "error")

    for pattern, label in SERVICE_PATTERNS:
        if pattern in line:
            return (f"bearcats {label}", "error")

    if any(p in line for p in HARD_ERROR_PATTERNS):
        return (line.strip()[:150], "error")

    return None


# Python writes a traceback to stderr one line at a time, so journald stores each
# line as its own record. These anchors start a block; everything that follows is
# glued on until the lines stop arriving.
TB_START = (
    "Traceback (most recent call last)",
    "Exception in ASGI application",
    "[APP-ERROR] unhandled exception",
)
EXC_LINE_RE = re.compile(r"^[\w.]*(?:Error|Exception|Warning|Timeout|Interrupt)\b")
LOG_PREFIX_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d[,\d]* \w+ [\w.]+: ")
INCIDENT_PATH_RE = re.compile(r"on (\w+) (\S+) \(user=")

# an unhandled exception is also logged by uvicorn and shows up again as a 5xx
# access line — remember what we just reported so it is only mailed once
_recent_incidents = {}
_recent_lock = threading.Lock()


def mark_incident(path: str):
    with _recent_lock:
        _recent_incidents[path] = time.time()
        for key in [k for k, v in _recent_incidents.items() if time.time() - v > 60]:
            del _recent_incidents[key]


def recent_incident(path: str) -> bool:
    with _recent_lock:
        return time.time() - _recent_incidents.get(path, 0) < ASGI_DUP_WINDOW


_deferred = []


def defer(unit: str, title: str, message: str, severity: str, path: str):
    """Hold an event for a moment in case a richer report of it shows up."""
    with _recent_lock:
        _deferred.append((time.time() + ACCESS_HOLD, unit, title, message, severity, path))


def drain_deferred(events: queue.Queue):
    now = time.time()
    with _recent_lock:
        due = [d for d in _deferred if d[0] <= now]
        if due:
            _deferred[:] = [d for d in _deferred if d[0] > now]
    for _due, unit, title, message, severity, path in due:
        if recent_incident(path):
            continue                      # already mailed with a traceback attached
        emit(events, unit, title, message, severity)


class TracebackBuffer:
    """Glue the lines of one traceback into a single alert."""

    def __init__(self, events: queue.Queue):
        self.events = events
        self.lock = threading.Lock()
        self.lines = []
        self.unit = ""
        self.anchor = ""
        self.last = 0.0
        self.last_app_error = 0.0

    def start(self, unit: str, line: str):
        if "[APP-ERROR]" in line:
            hit = INCIDENT_PATH_RE.search(line)
            if hit:
                mark_incident(hit.group(2))
        with self.lock:
            if self.lines:
                # chained exceptions repeat the "Traceback ..." header; keep one block
                self.lines.append(line)
                self.last = time.time()
                return
            self.lines = [line]
            self.unit = unit
            self.anchor = line
            self.last = time.time()

    def append(self, line: str) -> bool:
        with self.lock:
            if not self.lines:
                return False
            self.lines.append(line)
            self.last = time.time()
            return True

    def active(self) -> bool:
        with self.lock:
            return bool(self.lines)

    def maybe_flush(self):
        with self.lock:
            if self.lines and time.time() - self.last > TB_IDLE_FLUSH:
                self._flush_locked()

    def _flush_locked(self):
        block = "\n".join(self.lines)
        real = [l for l in self.lines if l.strip()]
        anchor, unit = self.anchor, self.unit
        self.lines, self.anchor = [], ""
        if not real:
            return

        exc = ""
        for line in reversed(real):
            stripped = line.strip()
            if line[:1] not in (" ", "\t") and EXC_LINE_RE.match(stripped):
                exc = stripped
                break
        exc = exc or real[-1].strip()

        now = time.time()
        if "[APP-ERROR]" in anchor:
            context = anchor.split("[APP-ERROR]", 1)[1].strip()
            hit = INCIDENT_PATH_RE.search(context)
            if hit:
                mark_incident(hit.group(2))
            context = context.replace("unhandled exception on ", "")
            title = f"{LOG_PREFIX_RE.sub('', exc)[:100]} — {context[:100]}"
            self.last_app_error = now
        elif "Exception in ASGI application" in anchor and now - self.last_app_error < ASGI_DUP_WINDOW:
            return          # our own middleware already reported this, with context
        else:
            title = LOG_PREFIX_RE.sub("", exc)[:150]
        emit(self.events, unit, title, block)


def journal_watcher(events: queue.Queue, state: State):
    """Follow journald for the app + nginx units."""
    tb = TracebackBuffer(events)

    def flusher():
        while True:
            time.sleep(0.5)
            try:
                tb.maybe_flush()
                drain_deferred(events)
            except Exception as exc:
                log(f"traceback flush failed: {exc}")

    threading.Thread(target=flusher, daemon=True).start()

    while True:
        try:
            cmd = ["journalctl", "-f", "-n", "0", "-o", "json",
                   "--output-fields=MESSAGE,_SYSTEMD_UNIT,PRIORITY"]
            for unit in JOURNAL_UNITS:
                cmd += ["-u", unit]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
            for raw in proc.stdout:
                try:
                    rec = json.loads(raw)
                except Exception:
                    continue
                message = rec.get("MESSAGE", "")
                if isinstance(message, list):
                    message = bytes(message).decode("utf-8", "replace")
                if not message:
                    continue
                unit = (rec.get("_SYSTEMD_UNIT") or "").replace(".service", "") or "system"

                # access lines never belong to a traceback
                access = ACCESS_RE.match(message)
                if access:
                    verdict = classify_app_line(message)
                    if verdict:
                        defer(unit, verdict[0], message, verdict[1],
                              access.group(3).split("?")[0])
                    continue

                if any(p in message for p in IGNORE_PATTERNS):
                    continue

                if any(s in message for s in TB_START):
                    if "\n" in message:                 # whole traceback in one record
                        tb.start(unit, message.split("\n")[0])
                        for line in message.split("\n")[1:]:
                            tb.append(line)
                    else:
                        tb.start(unit, message)
                    continue

                if tb.active():
                    tb.append(message)
                    continue

                verdict = classify_app_line(message)
                if verdict:
                    title, severity = verdict
                    emit(events, unit, title, message, severity)
                elif LEVEL_RE.match(message) and " WARNING " in message:
                    with state.lock:
                        state.counters["warning"] += 1
            proc.wait()
        except Exception as exc:
            log(f"journal watcher restarting after: {exc}")
        time.sleep(5)


def tail_file(path: str):
    """Yield new lines from a file, surviving rotation and truncation."""
    fh = None
    inode = None
    pos = 0
    while True:
        try:
            st = os.stat(path)
            if fh is None or st.st_ino != inode:
                if fh:
                    fh.close()
                fh = open(path, "r", errors="replace")
                inode = st.st_ino
                fh.seek(0, os.SEEK_END)     # only new lines
                pos = fh.tell()
            elif st.st_size < pos:          # truncated
                fh.seek(0)
                pos = 0
            line = fh.readline()
            if line:
                pos = fh.tell()
                yield line.rstrip("\n")
                continue
        except FileNotFoundError:
            if fh:
                fh.close()
                fh = None
        except Exception as exc:
            log(f"tail {path}: {exc}")
            if fh:
                fh.close()
                fh = None
        time.sleep(2)


_auth_limit_hits: dict = {}   # client ip -> [timestamps of cap_auth rate-limit trips]
_deny_hits: dict = {}         # client ip -> [timestamps of deny-rule 403s]


def _tripped(bucket: dict, client: str, trips: int, window: int, now: float) -> bool:
    """True once `client` has hit `bucket` `trips` times inside `window`; the
    streak then resets, so a persistent offender pages once per streak instead
    of once per request. Bounded at 5000 clients so a wide scan can't grow it
    without end."""
    hits = [t for t in bucket.get(client, []) if now - t < window]
    hits.append(now)
    bucket[client] = hits
    if len(bucket) > 5000:                      # bound memory under a wide scan
        for ip in [ip for ip, ts in bucket.items()
                   if not ts or now - ts[-1] >= window]:
            bucket.pop(ip, None)
    if len(hits) < trips:
        return False
    bucket[client] = []                         # alert once per streak, then re-arm
    return True


def auth_limit_worth_alerting(line: str, now: float = None) -> bool:
    """A nginx rate-limit line is only alert-worthy for the `cap_auth` zone once
    the same client has tripped it AUTH_LIMIT_TRIPS times inside
    AUTH_LIMIT_WINDOW. A link crawler walking every /signup?tier=... variant
    trips it once and is gone; a credential-stuffer keeps coming back. Other
    zones and non-rate-limit lines are untouched (returns True)."""
    m = LIMIT_REQ_RE.search(line)
    if not m or m.group(1) != "cap_auth":
        return True
    return _tripped(_auth_limit_hits, m.group(2), AUTH_LIMIT_TRIPS,
                    AUTH_LIMIT_WINDOW, time.time() if now is None else now)


def deny_worth_alerting(line: str, now: float = None) -> bool:
    """`access forbidden by rule` is the /static/ deny rule (.bak/.old/.swp/...)
    working as designed, and scanners probe those paths all day - one email per
    probe is pure noise, and fail2ban's noscript/secretprobe jails already ban
    the client. Alert only once one client trips it DENY_TRIPS times inside
    DENY_WINDOW, which is enumeration rather than a drive-by. Non-deny lines are
    untouched (returns True)."""
    m = DENY_RE.search(line)
    if not m:
        return True
    return _tripped(_deny_hits, m.group(1), DENY_TRIPS, DENY_WINDOW,
                    time.time() if now is None else now)


UPSTREAM_REFUSED = "(111: Connection refused) while connecting to upstream"
RESTART_GRACE = 90           # seconds after bearcats (re)starts that :8080 may refuse


def app_restarting() -> bool:
    """True while bearcats is stopping/starting or came up less than
    RESTART_GRACE seconds ago. Unattended upgrades restart it and the nightly
    auto-reboot takes it down; any request that lands in that ~30 s gap logs a
    refused upstream. A real outage still pages via health_watcher and the
    systemd crash patterns, so these lines are safe to drop in that window."""
    try:
        out = subprocess.run(
            ["systemctl", "show", "-p", "ActiveState",
             "-p", "ActiveEnterTimestampMonotonic", "bearcats"],
            capture_output=True, text=True, timeout=5).stdout
        props = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
        if props.get("ActiveState") != "active":
            return True
        since_start = time.monotonic() - int(props["ActiveEnterTimestampMonotonic"]) / 1e6
        return since_start < RESTART_GRACE
    except Exception:
        return False                         # unsure — alert as before


def file_watcher(events: queue.Queue, source: str, path: str):
    is_nginx = source == "nginx"
    for line in tail_file(path):
        if not line.strip() or any(p in line for p in IGNORE_PATTERNS):
            continue
        if is_nginx:
            m = NGINX_LEVEL_RE.search(line)
            if not m:
                continue
            if not auth_limit_worth_alerting(line):
                continue
            if not deny_worth_alerting(line):
                continue
            if UPSTREAM_REFUSED in line and app_restarting():
                continue
            title = line.split("] ", 1)[-1][:150]
            lm = LIMIT_REQ_RE.search(line)
            if lm and lm.group(1) == "cap_auth":
                title = (f"{lm.group(2)} tripped the auth rate limit "
                         f"{AUTH_LIMIT_TRIPS}x in {AUTH_LIMIT_WINDOW // 60} min")
            dm = DENY_RE.search(line)
            if dm:
                title = (f"{dm.group(1)} hit blocked paths "
                         f"{DENY_TRIPS}x in {DENY_WINDOW // 60} min")
            emit(events, "nginx", f"nginx {m.group(1)}: {title}", line)
        else:
            if any(p in line for p in FILE_ERROR_PATTERNS):
                emit(events, source, f"{source}: {line.strip()[:130]}", line)


def probe(url: str, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "cap-error-alerts/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def health_watcher(events: queue.Queue):
    down = {SITE_URL: 0, LOCAL_URL: 0}
    alerted = {SITE_URL: False, LOCAL_URL: False}
    time.sleep(20)                          # let the box settle after a reboot
    while True:
        for url in (SITE_URL, LOCAL_URL):
            label = "public site" if url == SITE_URL else "app (uvicorn :8080)"
            try:
                status = probe(url)
                ok = status < 500
                detail = f"HTTP {status}"
            except Exception as exc:
                ok = False
                detail = f"{type(exc).__name__}: {exc}"

            if ok:
                if alerted[url]:
                    emit(events, "health", f"RECOVERED — {label} is back up",
                         f"{url} responded {detail} after "
                         f"{down[url]} consecutive failed checks.", "warning")
                    alerted[url] = False
                down[url] = 0
            else:
                down[url] += 1
                if down[url] >= HEALTH_FAILURES_TO_ALERT and not alerted[url]:
                    emit(events, "health", f"DOWN — {label} is not responding",
                         f"{url} failed {down[url]} checks in a row.\nLast result: {detail}")
                    alerted[url] = True
        time.sleep(HEALTH_INTERVAL)


# ── One-shot modes ────────────────────────────────────────────────────────────

def send_test():
    sample = {
        "ts": time.time(),
        "source": "bearcats",
        "title": "Test alert — error email delivery check",
        "severity": "error",
        "text": ("Traceback (most recent call last):\n"
                 '  File "/home/recruiting/bearcats/main.py", line 4166, in upload_video\n'
                 "    s3.upload_fileobj(buf, SPACES_BUCKET, key)\n"
                 "botocore.exceptions.EndpointConnectionError: "
                 'Could not connect to the endpoint URL: "https://nyc3.digitaloceanspaces.com/"\n\n'
                 "(This is a test. Real alerts look exactly like this.)"),
        "count": 1,
        "first": time.time(),
    }
    text, html_body = render(sample)
    ok = send_email("[CAP ALERT] Test alert — delivery check", text, html_body)
    print("sent" if ok else "FAILED")
    return 0 if ok else 1


BASELINE_PATH = os.path.join(STATE_DIR, "heartbeat_baseline.json")


def send_heartbeat():
    """Weekly proof-of-life. Reports the delta since the last heartbeat, and
    never mutates the daemon's state file (that would reset dedupe history)."""
    state = State()
    baseline = {}
    try:
        with open(BASELINE_PATH) as fh:
            baseline = json.load(fh)
    except Exception:
        pass

    since = "the last 7 days"
    errors = state.counters.get("error", 0) - baseline.get("error", 0)
    warnings = state.counters.get("warning", 0) - baseline.get("warning", 0)
    errors, warnings = max(errors, 0), max(warnings, 0)
    cutoff = time.time() - 7 * 86400
    top = sorted(((k, v) for k, v in state.seen.items() if v["last"] > cutoff),
                 key=lambda kv: -kv[1]["count"])[:10]
    lines = [f"{v['count']:>4}x  {k.split('|', 1)[-1][:110]}" for k, v in top]
    body = (f"CAP Recruiting error watcher is running.\n\n"
            f"Errors alerted:  {errors}\n"
            f"Warnings seen:   {warnings}\n\n"
            + ("Most frequent signatures:\n" + "\n".join(lines) if lines else "No errors recorded.\n"))
    html_body = ("<div style=\"font-family:-apple-system,sans-serif\">"
                 "<h2>CAP Recruiting — watcher heartbeat</h2>"
                 f"<p>Still watching. In {since}: <b>{errors}</b> errors alerted, "
                 f"<b>{warnings}</b> warnings logged.</p>"
                 + ("<ul>" + "".join(f"<li><b>{v['count']}x</b> {html.escape(k.split('|', 1)[-1][:110])}</li>"
                                     for k, v in top) + "</ul>" if top
                    else "<p>No errors recorded — quiet week.</p>")
                 + "</div>")
    ok = send_email(f"[CAP] Weekly health: {errors} errors, {warnings} warnings", body, html_body)
    if ok:
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(BASELINE_PATH, "w") as fh:
                json.dump(dict(state.counters), fh)
        except Exception as exc:
            log(f"baseline write failed: {exc}")
    return 0 if ok else 1


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if "--test" in sys.argv:
        return send_test()
    if "--heartbeat" in sys.argv:
        return send_heartbeat()

    socket.setdefaulttimeout(30)
    state = State()
    events = queue.Queue(maxsize=5000)

    Dispatcher(state, events).start()
    threading.Thread(target=journal_watcher, args=(events, state), daemon=True).start()
    threading.Thread(target=health_watcher, args=(events,), daemon=True).start()
    for source, path in FILE_SOURCES:
        threading.Thread(target=file_watcher, args=(events, source, path), daemon=True).start()

    log(f"watching {', '.join(JOURNAL_UNITS)} + {len(FILE_SOURCES)} log files; alerts -> {ALERT_TO}")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main() or 0)
