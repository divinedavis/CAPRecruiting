import sqlite3
import boto3
from botocore.client import Config
from fastapi import FastAPI, Request, Form, Depends, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, distinct, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from starlette.middleware.sessions import SessionMiddleware
import re
import os
import asyncio
import uuid
import bcrypt
import stripe
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import logging
_logger = logging.getLogger("bearcats")

app = FastAPI()

# ── DigitalOcean Spaces (S3-compatible) ────────────────────────────────────────
SPACES_KEY    = os.environ.get("SPACES_KEY", "")
SPACES_SECRET = os.environ.get("SPACES_SECRET", "")
SPACES_REGION = os.environ.get("SPACES_REGION", "nyc3")
SPACES_BUCKET = os.environ.get("SPACES_BUCKET", "cap-recruiting-videos")
SPACES_ENDPOINT = f"https://{SPACES_REGION}.digitaloceanspaces.com"
SPACES_CDN_URL  = os.environ.get("SPACES_CDN_URL", "")

SMTP_HOST     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SITE_URL      = os.environ.get("SITE_URL", "https://bearcatrecruiting.com")
SPACES_BASE_URL = SPACES_CDN_URL if SPACES_CDN_URL else f"https://{SPACES_BUCKET}.{SPACES_REGION}.digitaloceanspaces.com"

s3 = boto3.client(
    "s3",
    region_name=SPACES_REGION,
    endpoint_url=SPACES_ENDPOINT,
    aws_access_key_id=SPACES_KEY,
    aws_secret_access_key=SPACES_SECRET,
    config=Config(signature_version="s3v4"),
)

# ── WebSocket Connection Manager ───────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        # user_id -> list of active WebSocket connections
        self.active: Dict[int, List[WebSocket]] = {}

    async def connect(self, user_id: int, ws: WebSocket):
        await ws.accept()
        if user_id not in self.active:
            self.active[user_id] = []
        self.active[user_id].append(ws)

    def disconnect(self, user_id: int, ws: WebSocket):
        if user_id in self.active:
            self.active[user_id] = [c for c in self.active[user_id] if c != ws]
            if not self.active[user_id]:
                del self.active[user_id]

    async def send_to_user(self, user_id: int, data: dict):
        if user_id in self.active:
            dead = []
            for ws in self.active[user_id]:
                try:
                    await ws.send_json(data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(user_id, ws)

manager = ConnectionManager()

_session_secret = os.environ.get("SESSION_SECRET", "")
if not _session_secret or _session_secret == "change-me":
    raise RuntimeError("SESSION_SECRET environment variable must be set to a strong random value")
SESSION_MAX_AGE = 86400  # 24 hours

# ── Message encryption at rest ─────────────────────────────────────────────────
from cryptography.fernet import Fernet
import hashlib, base64
_msg_key = base64.urlsafe_b64encode(hashlib.sha256(_session_secret.encode()).digest())
_fernet = Fernet(_msg_key)

def encrypt_message(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode()).decode()

def decrypt_message(ciphertext: str) -> str:
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except Exception:
        return ciphertext  # fallback for old unencrypted messages


app.add_middleware(SessionMiddleware, secret_key=_session_secret, https_only=True, same_site="lax", max_age=SESSION_MAX_AGE)


from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as _StarletteResponse

CSRF_EXEMPT_PATHS = {"/stripe/webhook", "/logout"}

class _CSRFMiddleware(BaseHTTPMiddleware):
    _SAFE = {"GET", "HEAD", "OPTIONS", "TRACE"}

    async def dispatch(self, request, call_next):
        if request.method not in self._SAFE and request.url.path not in CSRF_EXEMPT_PATHS:
            host = request.headers.get("host", "").split(":")[0]
            origin = request.headers.get("origin", "")
            referer = request.headers.get("referer", "")
            from urllib.parse import urlparse
            ok = False
            if origin:
                ok = urlparse(origin).hostname == host
            elif referer:
                ok = urlparse(referer).hostname == host
            if not ok:
                return _StarletteResponse("Forbidden: CSRF check failed", status_code=403)
        return await call_next(request)

app.add_middleware(_CSRFMiddleware)

class _SessionRefreshMiddleware(BaseHTTPMiddleware):
    """Re-verify is_admin and role from DB on every request so revoked
    privileges take effect immediately without requiring logout."""

    async def dispatch(self, request, call_next):
        user_id = request.session.get("user_id") if "session" in request.scope else None
        if user_id:
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.id == user_id).first()
                if user:
                    # Check session version — if mismatched, force logout
                    if request.session.get("session_version", 0) != (user.session_version or 0):
                        request.session.clear()
                    else:
                        request.session["is_admin"] = bool(user.is_admin)
                        request.session["role"] = user.role
                        request.session["subscription_tier"] = user.subscription_tier or "free"
                else:
                    request.session.clear()
            finally:
                db.close()
        return await call_next(request)

app.add_middleware(_SessionRefreshMiddleware)

class _BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject non-upload POST requests with bodies larger than 1MB."""
    _UPLOAD_PATHS = {"/profile/upload-photo", "/profile/videos/upload",
                     "/profile/images/upload", "/profile/transcripts/upload"}
    _MAX_BODY = 1 * 1024 * 1024  # 1MB

    async def dispatch(self, request, call_next):
        if request.method == "POST":
            is_upload = any(request.url.path.startswith(p) for p in self._UPLOAD_PATHS)
            if not is_upload:
                cl = request.headers.get("content-length")
                if cl and int(cl) > self._MAX_BODY:
                    return _StarletteResponse("Request body too large", status_code=413)
        return await call_next(request)

app.add_middleware(_BodySizeLimitMiddleware)



from starlette.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://caprecruiting.com", "https://www.caprecruiting.com", "https://bearcatrecruiting.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)



SQLALCHEMY_DATABASE_URL = "sqlite:////home/recruiting/bearcats/recruiting.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ── Models ─────────────────────────────────────────────────────────────────────

class Team(Base):
    __tablename__ = "teams"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)  # 'player' or 'coach'
    is_admin = Column(Boolean, default=False)
    subscription_tier = Column(String, default="free")  # free, essentials, advanced, premium
    stripe_customer_id = Column(String, default="")
    stripe_subscription_id = Column(String, default="")
    in_person_paid_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    session_version = Column(Integer, default=0)
    public_id = Column(String, unique=True, index=True)

class PlayerProfile(Base):
    __tablename__ = "player_profiles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)
    first_name = Column(String, default="")
    last_name = Column(String, default="")
    position = Column(String, default="")
    year = Column(String, default="")
    height = Column(String, default="")
    weight = Column(String, default="")
    forty_yard = Column(String, default="")
    bench_press = Column(String, default="")
    vertical = Column(String, default="")
    squat = Column(String, default="")
    clean = Column(String, default="")
    broad_jump = Column(String, default="")
    pro_agility = Column(String, default="")
    wingspan = Column(String, default="")
    gpa = Column(String, default="")
    school = Column(String, default="")
    city = Column(String, default="")
    state = Column(String, default="")
    bio = Column(Text, default="")
    link1_label = Column(String, default="")
    link1_url = Column(String, default="")
    link2_label = Column(String, default="")
    link2_url = Column(String, default="")
    link3_label = Column(String, default="")
    link3_url = Column(String, default="")
    photo = Column(String, default="")
    hudl_url = Column(String, default="")
    x_url = Column(String, default="")
    instagram_url = Column(String, default="")
    offer1 = Column(String, default="")
    offer2 = Column(String, default="")
    offer3 = Column(String, default="")
    offer4 = Column(String, default="")
    offer5 = Column(String, default="")
    visit1_school = Column(String, default="")
    visit1_date   = Column(String, default="")
    visit2_school = Column(String, default="")
    visit2_date   = Column(String, default="")
    visit3_school = Column(String, default="")
    visit3_date   = Column(String, default="")
    visit4_school = Column(String, default="")
    visit4_date   = Column(String, default="")
    visit5_school = Column(String, default="")
    visit5_date   = Column(String, default="")
    phone = Column(String, default="")
    contact_email = Column(String, default="")
    stars = Column(Integer, default=0)
    ncaa_eligibility_num = Column(String, default="")
    intended_major = Column(String, default="")

class CoachProfile(Base):
    __tablename__ = "coach_profiles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)
    first_name = Column(String, default="")
    last_name = Column(String, default="")
    school = Column(String, default="")
    title = Column(String, default="")
    division = Column(String, default="")
    conference = Column(String, default="")
    bio = Column(Text, default="")
    link1_label = Column(String, default="")
    link1_url = Column(String, default="")
    link2_label = Column(String, default="")
    link2_url = Column(String, default="")
    photo = Column(String, default="")
    phone = Column(String, default="")
    contact_email = Column(String, default="")
    college = Column(String, default="")

class Video(Base):
    __tablename__ = "videos"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String, default="")
    url = Column(String, nullable=False)
    embed_url = Column(String, nullable=False)
    thumbnail_url = Column(String, default="")
    is_pinned = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Photo(Base):
    __tablename__ = "photos"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String, default="")
    url = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Transcript(Base):
    __tablename__ = "transcripts"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String, default="")
    file_url = Column(String, nullable=False)
    filename = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String, nullable=False, unique=True)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Integer, default=0)

class CoachInvite(Base):
    __tablename__ = "coach_invites"
    id = Column(Integer, primary_key=True)
    token = Column(String, nullable=False, unique=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    used_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    note = Column(String, default="")

class ProfileImage(Base):
    __tablename__ = "profile_images"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    file_url = Column(String, nullable=False)
    is_pinned = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Evaluation(Base):
    __tablename__ = "evaluations"
    id = Column(Integer, primary_key=True)
    player_id = Column(Integer, ForeignKey("users.id"))
    coach_id  = Column(Integer, ForeignKey("users.id"))
    content   = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    read = Column(Boolean, default=False)
    deleted_by_sender = Column(Boolean, default=False)
    deleted_by_receiver = Column(Boolean, default=False)


class LegalContract(Base):
    __tablename__ = "legal_contracts"
    id = Column(Integer, primary_key=True)
    token = Column(String(64), unique=True, nullable=False)
    player_name = Column(String, nullable=False)
    status = Column(String, default="pending")   # pending / signed
    signed_pdf_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signer_ip = Column(String, nullable=True)
    hidden = Column(Boolean, default=False)


class InPersonPaymentToken(Base):
    __tablename__ = "in_person_payment_tokens"
    id         = Column(Integer, primary_key=True)
    token      = Column(String, unique=True, nullable=False, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used_at    = Column(DateTime, nullable=True)



class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=False, index=True)
    username = Column(String, default="")
    attempted_at = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=False)


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_log"
    id = Column(Integer, primary_key=True)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String, nullable=False)
    target_id = Column(Integer, nullable=True)
    detail = Column(Text, default="")
    ip_address = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ── Helpers ────────────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="/home/recruiting/bearcats/static"), name="static")
app.mount("/.well-known", StaticFiles(directory="/home/recruiting/bearcats/static/.well-known"), name="well-known")
templates = Jinja2Templates(directory="/home/recruiting/bearcats/templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _generate_public_id() -> str:
    return uuid.uuid4().hex[:12]

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())




def validate_password_strength(password: str) -> str:
    """Return error message if password is weak, or empty string if OK."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one number."
    if not re.search(r'[^A-Za-z0-9]', password):
        return "Password must contain at least one special character."
    return ""

MAX_LOGIN_ATTEMPTS = 10
LOGIN_LOCKOUT_MINUTES = 15

def check_login_lockout(db: Session, ip: str) -> bool:
    """Return True if the IP is currently locked out."""
    cutoff = datetime.utcnow() - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
    recent_failures = db.query(LoginAttempt).filter(
        LoginAttempt.ip_address == ip,
        LoginAttempt.success == False,
        LoginAttempt.attempted_at > cutoff
    ).count()
    return recent_failures >= MAX_LOGIN_ATTEMPTS

def record_login_attempt(db: Session, ip: str, username: str, success: bool):
    """Record a login attempt for rate limiting."""
    db.add(LoginAttempt(ip_address=ip, username=username, success=success))
    db.commit()
    # Clean up old login attempts (older than 24 hours)
    old_cutoff = datetime.utcnow() - timedelta(hours=24)
    db.query(LoginAttempt).filter(LoginAttempt.attempted_at < old_cutoff).delete()
    db.commit()


def log_admin_action(db: Session, admin_id: int, action: str, target_id: int = None, detail: str = "", ip: str = ""):
    db.add(AdminAuditLog(admin_id=admin_id, action=action, target_id=target_id, detail=detail, ip_address=ip))
    db.commit()

def unread_sender_count(db: Session, user_id: int) -> int:
    """Count unique senders who have unread messages for user_id."""
    result = db.query(func.count(distinct(Message.sender_id))).filter(
        Message.receiver_id == user_id,
        Message.read == False
    ).scalar()
    return result or 0



# ── Stripe Config ──────────────────────────────────────────────────────────────
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET  = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICES = {
    "essentials": os.environ.get("STRIPE_PRICE_ESSENTIALS", ""),
    "advanced":   os.environ.get("STRIPE_PRICE_ADVANCED", ""),
    "premium":    os.environ.get("STRIPE_PRICE_PREMIUM", ""),
}
STRIPE_PRICES_YEARLY = {
    "essentials": os.environ.get("STRIPE_PRICE_ESSENTIALS_YEARLY", ""),
    "advanced":   os.environ.get("STRIPE_PRICE_ADVANCED_YEARLY", ""),
    "premium":    os.environ.get("STRIPE_PRICE_PREMIUM_YEARLY", ""),
}

# ── Subscription Tier Helpers ──────────────────────────────────────────────────
TIER_ORDER = {"free": 0, "essentials": 1, "advanced": 2, "premium": 3}

def tier_gte(tier: str, required: str) -> bool:
    return TIER_ORDER.get(tier or "free", 0) >= TIER_ORDER.get(required, 0)

def viewer_tier(user) -> str:
    """Kept for compatibility — now unused for gating. Gating is on the player's tier."""
    if user is None:
        return "free"
    return "premium"  # viewers (coaches/admins) always see whatever the player exposes

def player_tier(target_user) -> str:
    """Return the tier of the player being viewed — this controls what coaches can see."""
    if target_user is None:
        return "free"
    if target_user.is_admin:
        return "premium"
    return target_user.subscription_tier or "free"


def _safe_redirect(url: str, fallback: str = "/profile/edit") -> str:
    """Only allow relative redirects to prevent open redirect attacks."""
    if url and url.startswith("/") and not url.startswith("//"):
        return url
    return fallback

VIDEO_ALLOWED_EXTENSIONS = {"mp4", "mov", "webm", "avi", "mkv"}
VIDEO_MAX_BYTES = 4 * 1024 * 1024 * 1024  # 4 GB

TRANSCRIPT_ALLOWED_EXTENSIONS = {"pdf", "doc", "docx"}
TRANSCRIPT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
TRANSCRIPT_MAX_COUNT = 4
IMAGE_MAX_COUNT = 20
IMAGE_MAX_BYTES = 10 * 1024 * 1024
IMAGE_ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
IMAGE_CONTENT_TYPES = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif", "webp": "image/webp"}
TRANSCRIPT_CONTENT_TYPES = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


# ── Football Questionnaire Data ────────────────────────────────────────────────
QUESTIONNAIRE_DATA = {
    "D1": {
        "ACC": {
            "California": "https://college.jumpforward.com/questionnaire.aspx?iid=350&sportid=18",
            "Clemson": "https://questionnaires.armssoftware.com/4792442e8b01",
            "Duke": "https://questionnaires.armssoftware.com/fea53f18262f",
            "Georgia Tech": "https://ramblinwreck.com/student-athlete-questionnaire/",
            "Louisville": "https://questionnaires.armssoftware.com/04c70af73d18",
            "NC State": "https://questionnaires.armssoftware.com/fa5122606469",
            "North Carolina": "https://goheels.com/form/6",
            "Pitt": "https://questionnaires.armssoftware.com/b0c551579d60",
            "SMU": "https://questionnaires.armssoftware.com/af6eb6d29764",
            "Stanford": "https://questionnaires.armssoftware.com/a1565868bdbf",
            "Syracuse": "https://cuse.com/form/3",
            "Virginia": "https://questionnaires.armssoftware.com/5eb2b0c4eed7",
            "Virginia Tech": "https://college.jumpforward.com/questionnaire.aspx?iid=472&sportid=18",
            "Wake Forest": "https://questionnaires.armssoftware.com/b35995e9775c",
        },
        "Big Ten": {
            "Maryland": "https://questionnaires.armssoftware.com/b37f2f0aac44",
            "Nebraska": "https://questionnaires.armssoftware.com/d388bb15000c",
            "Northwestern": "https://questionnaires.armssoftware.com/be4d150daff0",
            "Penn State": "https://questionnaires.armssoftware.com/24b0eed6eb01",
            "Rutgers": "https://questionnaires.armssoftware.com/581588caf234",
            "UCLA": "https://questionnaires.armssoftware.com/74c822368ab9",
            "Washington": "https://www.fieldlevel.com/washington/football/recruiting",
            "Wisconsin": "https://questionnaires.armssoftware.com/73384a600a7f",
        },
        "Conference USA": {
            "Jax State": "https://jaxstatesports.com/sb_output.aspx?form=3",
            "Kennesaw State": "https://college.jumpforward.com/questionnaire.aspx?iid=394&sportid=54",
            "LA Tech": "https://questionnaires.armssoftware.com/ae17badbf668",
            "Liberty": "https://questionnaires.armssoftware.com/174fa9a5d8bc",
            "MTSU": "https://questionnaires.armssoftware.com/3cbdaac68e8e",
            "Missouri State": "https://questionnaires.armssoftware.com/00d6863851cf",
            "NM State": "https://nmstate.collegewarroom.com/Questionnaire/Form/1",
            "Sam Houston": "https://questionnaires.armssoftware.com/6a16f89fe9a4?path=football",
            "UTEP": "https://utepminers.com/sb_output.aspx?form=1034",
        },
        "MAC": {
            "Akron": "https://questionnaires.armssoftware.com/3242f548bc75",
            "Ball State": "https://questionnaires.armssoftware.com/489a56db71f3",
            "Bowling Green": "https://questionnaires.armssoftware.com/da9ecb9101b1",
            "Buffalo": "https://questionnaires.armssoftware.com/c2ff35d2eb21",
            "Central Michigan": "https://cmuchippewas.com/sports/2018/7/6/ot-questionnaires-html",
            "Eastern Michigan": "https://questionnaires.armssoftware.com/0b95647b5489?path=football",
            "Miami (OH)": "https://questionnaires.armssoftware.com/8ec82a98b444",
            "Northern Illinois": "https://questionnaires.armssoftware.com/b09a8d2fd723",
            "Ohio": "https://questionnaires.armssoftware.com/233a2d93ee59",
            "Toledo": "https://questionnaires.armssoftware.com/97ef9cb72419",
            "UMass": "https://questionnaires.armssoftware.com/f2df0deb984d",
            "Western Michigan": "https://qwiku.qwikrecruiting.com/questionnaire/62de960634dde90030c1a7b2",
        },
        "SEC": {
            "Arkansas Razorbacks": "https://questionnaires.armssoftware.com/567edf1eacb2",
            "Auburn Tigers": "https://questionnaires.armssoftware.com/88084278386f",
            "Kentucky Wildcats": "https://ukathletics.com/recruits/",
            "Mississippi State Bulldogs": "https://tickets.formstack.com/forms/mississippi_state_football_questionnaire",
            "Vanderbilt Commodores": "https://vanderbilt.collegewarroom.com/Questionnaire/Form/1",
        },
        "Sun Belt": {
            "App State": "https://appstatesports.com/sb_output.aspx?form=37",
            "Arkansas State": "https://college.jumpforward.com/questionnaire.aspx?iid=308&sportid=18&path=football",
            "Coastal Carolina": "https://questionnaires.armssoftware.com/6814c0767b73",
            "Georgia State": "https://georgiastatesports.com/sb_output.aspx?form=94",
            "James Madison": "https://questionnaires.armssoftware.com/b649b94cfffd",
            "Old Dominion": "https://questionnaires.armssoftware.com/68685a2e9eda",
            "Southern Miss": "https://questionnaires.armssoftware.com/8714178713d4",
            "Texas State": "https://txst.com/sb_output.aspx?form=26",
            "Troy": "https://troytrojans.com/form/3",
            "ULM": "https://ulmwarhawks.com/sb_output.aspx?form=7",
        },
    },
    "D2": {
        "Mountain East": {
            "Charleston": "https://questionnaires.armssoftware.com/42478c4f940f",
            "Fairmont State": "https://questionnaires.armssoftware.com/403e032f0bd0",
            "Frostburg State": "https://questionnaires.armssoftware.com/210375186406",
            "West Liberty": "https://hilltoppersports.com/sb_output.aspx?form=3",
            "West Virginia State": "https://wvsuyellowjackets.com/sb_output.aspx?form=3",
            "West Virginia Wesleyan": "https://college.jumpforward.com/questionnaire.aspx?iid=1713&sportid=54",
            "Wheeling": "https://wucardinals.com/sb_output.aspx?form=3&tab=recruitme",
        },
        "NE10": {
            "American International": "https://questionnaires.armssoftware.com/a3e03c079bb4",
            "Assumption": "https://questionnaires.armssoftware.com/b100ccaa730a",
            "Bentley": "https://questionnaires.armssoftware.com/de9c5d168823",
            "Franklin Pierce": "https://questionnaires.armssoftware.com/7ceb526a27b9",
            "Pace": "https://questionnaires.armssoftware.com/a347f4725a3f",
            "Post": "https://posteagles.com/sb_output.aspx?form=8&path=sprtftb",
            "Saint Anselm": "https://questionnaires.armssoftware.com/3bd072bd5f12",
            "Southern Connecticut": "https://scsuowls.com/sb_output.aspx?form=3",
        },
        "PSAC": {
            "Bloomsburg": "https://questionnaires.armssoftware.com/d135bff4cb3f",
            "Cal PA": "https://questionnaires.armssoftware.com/aae478e664c7",
            "Clarion": "https://questionnaires.armssoftware.com/b1bc7e4964fe",
            "East Stroudsburg": "https://questionnaires.armssoftware.com/c096c4aa54b2",
            "Edinboro": "https://questionnaires.armssoftware.com/e8af82bc02e1",
            "Gannon": "https://questionnaires.armssoftware.com/a548a8143ff9",
            "IUP": "https://iupathletics.com/sports/2013/9/12/GEN_0912135915.aspx",
            "Kutztown": "https://questionnaires.armssoftware.com/b53971ecd6df",
            "Lock Haven": "https://questionnaires.armssoftware.com/4b0148820178",
            "Millersville": "https://questionnaires.armssoftware.com/2b06d027b120",
            "Seton Hill": "https://questionnaires.armssoftware.com/eb07191a467b",
            "Sheppard": "https://questionnaires.armssoftware.com/1df2f096dcf5",
            "Shippensburg": "https://questionnaires.armssoftware.com/ac510ffd1962",
            "Slippery Rock": "https://questionnaires.armssoftware.com/2ff1d7f558a8",
            "West Chester": "https://questionnaires.armssoftware.com/023ce109bb90",
        },
    },
    "D3": {
        "Centennial": {
            "Carnegie Mellon": "https://athletics.cmu.edu/sports/fball/recruitQ",
            "Dickinson": "https://dickinsonathletics.com/sports/2022/8/2/football-recruit-questionnaire.aspx",
            "Franklin & Marshall": "https://questionnaires.armssoftware.com/ce4f3c984618",
            "Gettysburg": "https://gettysburgsports.com/sports/2015/10/12/FB_1012154923.aspx",
            "Johns Hopkins": "https://questionnaires.armssoftware.com/f0c7092fb543",
            "Mcdaniel": "https://mcdanielathletics.com/sports/2022/4/29/recruits-football",
            "Muhlenberg": "https://questionnaires.armssoftware.com/ee1e2fc84d1b",
            "Ursinus": "https://www.frontrush.com/FR_Web_App/Player/PlayerSubmit.aspx?sid=MTE2Nzc=-QVSswpzoAIc=&ptype=recruit",
        },
        "MAC": {
            "Albright": "https://www.frontrush.com/FR_Web_App/Player/PlayerSubmit.aspx?sid=MTMzNjY=-BjIqwRbsEzs=&ptype=recruit",
            "Alvernia": "https://auwolves.com/sb_output.aspx?frform=11&path=football",
            "Delaware Valley": "https://athletics.delval.edu/sb_output.aspx?form=9",
            "Eastern": "https://docs.google.com/forms/d/e/1FAIpQLSdYlSOw96JKrfEsjd8C0LA0bT1GaYBLCKo7iBYujwXfbvmQCw/viewform",
            "FDU-Florham": "https://www.frontrush.com/FR_Web_App/Player/PlayerSubmit.aspx?sid=ODE5Nw==-ThHxzxPokRs=&ptype=recruit",
            "King's": "https://www.frontrush.com/FR_Web_App/Player/PlayerSubmit.aspx?sid=MjI3Njc=-i4vWXOVFeUA=&ptype=recruit",
            "Lebanon Valley": "https://questionnaires.armssoftware.com/161261360190?path=football",
            "Misericordia": "https://athletics.misericordia.edu/sb_output.aspx?frform=16",
            "Stevenson": "https://questionnaires.armssoftware.com/9441858d75d8",
            "Widener": "https://docs.google.com/forms/u/1/d/e/1FAIpQLSfU6rF5jlQfZkE1WjO6cmRoXUNEgfWSHPBCxk_sNC0FvXowNw/viewform",
        },
    },
}
# ── College offer division lookup (mirrors CFBD data in edit_profile.html) ────
_OFFER_DIV = {}
_CFBD = {
  "D1": [
    "Boston College","Clemson","Duke","Florida State","Georgia Tech","Louisville","Miami (FL)","NC State","North Carolina","Pittsburgh","SMU","Stanford","Syracuse","Virginia","Virginia Tech","Wake Forest",
    "Illinois","Indiana","Iowa","Maryland","Michigan","Michigan State","Minnesota","Nebraska","Northwestern","Ohio State","Oregon","Penn State","Purdue","Rutgers","UCLA","USC","Washington","Wisconsin",
    "Arizona","Arizona State","Baylor","BYU","Cincinnati","Colorado","Houston","Iowa State","Kansas","Kansas State","Oklahoma State","TCU","Texas Tech","UCF","Utah","West Virginia",
    "Alabama","Arkansas","Auburn","Florida","Georgia","Kentucky","LSU","Mississippi State","Missouri","Oklahoma","Ole Miss","South Carolina","Tennessee","Texas","Texas A&M","Vanderbilt",
    "Charlotte","East Carolina","FAU","Memphis","North Texas","Rice","South Florida","Tulane","Tulsa","UTSA",
    "FIU","Jacksonville State","Kennesaw State","Liberty","Louisiana Tech","Middle Tennessee","New Mexico State","Sam Houston","UTEP","Western Kentucky",
    "Akron","Ball State","Bowling Green","Buffalo","Central Michigan","Eastern Michigan","Kent State","Miami (OH)","Northern Illinois","Ohio","Toledo","Western Michigan",
    "Air Force","Boise State","Colorado State","Fresno State","Hawaii","Nevada","New Mexico","San Diego State","San Jose State","UNLV","Utah State","Wyoming",
    "Appalachian State","Arkansas State","Coastal Carolina","Georgia Southern","Georgia State","James Madison","Louisiana","Louisiana Monroe","Marshall","Old Dominion","South Alabama","Southern Miss","Texas State","Troy",
    "Army","Connecticut","Massachusetts","Navy","Notre Dame",
    "Delaware","Elon","Hampton","Maine","Monmouth","New Hampshire","Rhode Island","Richmond","Stony Brook","Towson","Villanova","William & Mary",
    "Illinois State","Indiana State","Missouri State","Murray State","North Dakota State","Northern Iowa","South Dakota","South Dakota State","Southern Illinois","Youngstown State",
    "Austin Peay","Bellarmine","Charleston Southern","Eastern Kentucky","Gardner-Webb","Lindenwood","Morehead State","North Alabama","Presbyterian","Robert Morris","SE Missouri State","Tennessee State","Tennessee Tech","UT Martin",
    "Chattanooga","East Tennessee State","Furman","Mercer","Samford","The Citadel","VMI","Western Carolina","Wofford",
    "Houston Christian","Incarnate Word","Lamar","McNeese","Nicholls","Northwestern State","SE Louisiana","Stephen F. Austin","Tarleton State",
    "Alabama A&M","Alabama State","Alcorn State","Arkansas-Pine Bluff","Bethune-Cookman","Florida A&M","Grambling","Jackson State","Mississippi Valley State","Prairie View A&M","Southern","Texas Southern",
    "Delaware State","Howard","Morgan State","Norfolk State","North Carolina A&T","North Carolina Central","South Carolina State",
    "Bucknell","Colgate","Fordham","Georgetown","Holy Cross","Lafayette","Lehigh",
    "Butler","Campbell","Davidson","Dayton","Drake","Marist","San Diego","Stetson","Valparaiso",
    "Bryant","Central Connecticut","Duquesne","LIU","Merrimack","Sacred Heart","Saint Francis","Stonehill",
    "North Dakota","Southern Utah","UC Davis"
  ],
  "D2": [
    "Bowie State","Elizabeth City State","Fayetteville State","Johnson C. Smith","Livingstone","Shaw","Virginia State","Virginia Union","Winston-Salem State",
    "Davenport","Ferris State","Grand Valley State","Michigan Tech","Northwood","Saginaw Valley State","Tiffin","Wayne State (MI)",
    "Azusa Pacific","Cal Poly Humboldt","Chico State","Simon Fraser","Western Oregon",
    "Christian Brothers","Delta State","Shorter","West Alabama","West Florida","West Georgia",
    "Emporia State","Fort Hays State","Missouri Southern","Missouri Western","Pittsburg State","Washburn",
    "Alderson Broaddus","Concord","Fairmont State","Frostburg State","Glenville State","Notre Dame (OH)","Salem","West Liberty","West Virginia State","West Virginia Wesleyan","Wheeling",
    "American International","Assumption","Bentley","New Haven","Southern Connecticut",
    "Augustana (SD)","Bemidji State","Minnesota Duluth","Minnesota State","Minot State","Northern State","Sioux Falls","Southwest Minnesota State","Upper Iowa","Wayne State (NE)","Winona State",
    "Bloomsburg","California (PA)","Clarion","East Stroudsburg","Edinboro","IUP","Kutztown","Lock Haven","Mansfield","Millersville","Shippensburg","Slippery Rock",
    "Adams State","Black Hills State","Chadron State","Colorado Mesa","Colorado School of Mines","Fort Lewis","New Mexico Highlands","South Dakota Mines","Western Colorado",
    "Carson-Newman","Catawba","Lenoir-Rhyne","Mars Hill","Newberry","Tusculum","Wingate",
    "Albany State","Clark Atlanta","Fort Valley State","Kentucky State","Lane","Miles","Morehouse","Savannah State","Stillman","Tuskegee",
    "Angelo State","Eastern New Mexico","Midwestern State","Sul Ross State","Texas A&M-Commerce","Texas A&M-Kingsville","West Texas A&M",
    "Barton","Limestone","North Greenville","Young Harris"
  ],
  "D3": [
    "Carthage","Elmhurst","Illinois Wesleyan","Millikin","North Central","North Park","Wheaton (IL)",
    "Dickinson","Franklin & Marshall","Gettysburg","Johns Hopkins","McDaniel","Muhlenberg","Ursinus","Washington (MD)",
    "Curry","Endicott","Maine Maritime","Salve Regina","Western New England",
    "Alfred","Hartwick","Ithaca","Morrisville State","St. John Fisher","Utica",
    "Catholic","Drew","Juniata","Moravian","Susquehanna",
    "Hobart","RPI","Rochester","St. Lawrence","Union (NY)",
    "Delaware Valley","King's","Lycoming","Misericordia","Wilkes",
    "Albright","Lebanon Valley","Messiah","Widener",
    "Adrian","Albion","Alma","Calvin","Hope","Kalamazoo","Olivet","Trine",
    "Augsburg","Bethel (MN)","Carleton","Concordia (MN)","Gustavus Adolphus","Hamline","Macalester","St. John's (MN)","St. Olaf","St. Thomas",
    "Carroll","Grinnell","Knox","Lake Forest","Lawrence","Monmouth (IL)","Ripon","St. Norbert",
    "Amherst","Bates","Bowdoin","Colby","Hamilton","Middlebury","Trinity (CT)","Tufts","Wesleyan","Williams",
    "Kean","Montclair State","Rowan","William Paterson",
    "Allegheny","Denison","DePauw","Hiram","Kenyon","Oberlin","Ohio Wesleyan","Wabash","Wittenberg","Wooster",
    "Baldwin Wallace","Capital","Heidelberg","Marietta","Mount Union","Muskingum","Ohio Northern","Otterbein",
    "Averett","Bridgewater (VA)","Eastern Mennonite","Guilford","Hampden-Sydney","Randolph-Macon","Shenandoah","Washington & Lee",
    "Bethany (WV)","Carnegie Mellon","Geneva","Grove City","Thiel","Washington & Jefferson","Waynesburg","Westminster (PA)",
    "Cal Lutheran","Chapman","Claremont-Mudd-Scripps","La Verne","Occidental","Redlands","Whittier",
    "Berry","Centre","Hendrix","Millsaps","Oglethorpe","Rhodes","Sewanee","Trinity (TX)",
    "Case Western Reserve","Chicago","Emory","NYU","Rochester","Wash U",
    "UW-Eau Claire","UW-La Crosse","UW-Oshkosh","UW-Platteville","UW-River Falls","UW-Stevens Point","UW-Stout","UW-Whitewater",
    "Benedictine (IL)","Bethel (TN)","Brockport","Buffalo State","Cortland","Defiance","Dubuque","East Texas Baptist","Ferrum","Greenville","Hardin-Simmons","Huntingdon","John Carroll","Linfield","Luther","Mary Hardin-Baylor","McMurry","Mississippi College","Mount St. Joseph","Nebraska Wesleyan","North Central (MN)","Norwich","Pacific Lutheran","Puget Sound","Southwestern (TX)","Texas Lutheran","Thomas More","Wartburg","Whitworth","Wisconsin Lutheran"
  ]
}
for _div, _schools in _CFBD.items():
    for _s in _schools:
        _OFFER_DIV[_s] = _div

def _offer_div_counts(profile):
    """Return (d1, d2, d3) offer counts for a player profile."""
    counts = {"D1": 0, "D2": 0, "D3": 0}
    if not profile:
        return counts
    for field in (profile.offer1, profile.offer2, profile.offer3, profile.offer4, profile.offer5):
        if field:
            div = _OFFER_DIV.get(field.strip())
            if div:
                counts[div] += 1
    return counts


@app.on_event("startup")
async def _startup_migrations():
    """Run one-time data migrations on startup if needed."""
    db = SessionLocal()
    try:
        # Backfill public_id for existing users that don't have one
        from sqlalchemy import text
        users_without_pid = db.query(User).filter(
            (User.public_id == None) | (User.public_id == "")
        ).all()
        for u in users_without_pid:
            u.public_id = _generate_public_id()
        if users_without_pid:
            db.commit()
    finally:
        db.close()

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=302)
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/pricing", response_class=HTMLResponse)
async def pricing_page(request: Request):
    return templates.TemplateResponse("pricing.html", {"request": request})

@app.get("/signup", response_class=HTMLResponse)
async def signup_get(request: Request, db: Session = Depends(get_db), invite: str = None, tier: str = "essentials", billing: str = "monthly", bypass_token: str = None):
    teams = db.query(Team).order_by(Team.name).all()
    invite_valid = False
    invite_error = None
    if invite:
        inv = db.query(CoachInvite).filter(CoachInvite.token == invite, CoachInvite.used == False).first()
        if inv and inv.expires_at > datetime.utcnow():
            invite_valid = True
        else:
            invite_error = "This invite link is invalid or has expired."
    if bypass_token:
        tier = "premium"
        billing = "monthly"
    return templates.TemplateResponse("signup.html", {
        "request": request, "error": invite_error, "teams": teams,
        "selected_team_id": None, "invite_token": invite if invite_valid else None,
        "invite_valid": invite_valid,
        "selected_tier": tier,
        "selected_billing": billing,
        "bypass_token": bypass_token,
    })

@app.post("/signup", response_class=HTMLResponse)
async def signup_post(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("player"),
    tier: str = Form("essentials"),
    billing: str = Form("monthly"),
    team_id: Optional[int] = Form(None),
    coach_team_id: Optional[int] = Form(None),
    new_team_name: str = Form(""),
    school_name: str = Form(""),
    school_city: str = Form(""),
    school_state: str = Form(""),
    coach_division: str = Form(""),
    coach_conference: str = Form(""),
    coach_college: str = Form(""),
    invite_token: Optional[str] = Form(None),
    bypass_token: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    username = username.strip()
    new_team_name = new_team_name.strip()
    teams = db.query(Team).order_by(Team.name).all()

    def err(msg):
        return templates.TemplateResponse("signup.html", {
            "request": request, "error": msg,
            "teams": teams, "selected_team_id": team_id,
            "selected_tier": tier, "selected_billing": billing,
            "invite_token": invite_token, "invite_valid": bool(invite_token),
            "bypass_token": bypass_token,
        })

    if role not in ("player", "coach"):
        return err("Invalid role selected.")
    if role == "coach":
        if not invite_token:
            return err("Coach accounts require an invite link. Please contact an admin.")
        inv = db.query(CoachInvite).filter(CoachInvite.token == invite_token, CoachInvite.used == False).first()
        if not inv or inv.expires_at <= datetime.utcnow():
            return err("This invite link is invalid or has expired.")
    if role == "player" and not school_name.strip():
        return err("Players must select their high school.")
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return err("Please enter a valid email address.")
    if len(username) > 30:
        return err("Username must be 30 characters or fewer.")
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return err("Username can only contain letters, numbers, underscores, dots, and hyphens (no spaces).")
    if db.query(User).filter(User.username == username).first():
        return err("Username already taken.")
    if db.query(User).filter(User.email == email).first():
        return err("Email already registered.")
    pw_err = validate_password_strength(password)
    if pw_err:
        return err(pw_err)

    # Resolve coach team: create new team if name provided, else use selected id
    coach_tid = None
    if role == "coach":
        if new_team_name:
            if len(new_team_name) > 100:
                return err("Team name is too long (max 100 characters).")
            existing_team = db.query(Team).filter(Team.name == new_team_name).first()
            if existing_team:
                coach_tid = existing_team.id
            else:
                created = Team(name=new_team_name)
                db.add(created)
                db.commit()
                db.refresh(created)
                coach_tid = created.id
        elif coach_team_id and db.query(Team).filter(Team.id == coach_team_id).first():
            coach_tid = coach_team_id

    user = User(username=username, email=email, password_hash=hash_password(password), role=role, public_id=_generate_public_id())
    db.add(user)
    db.commit()
    db.refresh(user)

    if role == "player":
        db.add(PlayerProfile(user_id=user.id, team_id=team_id, school=school_name.strip(), city=school_city.strip(), state=school_state.strip()))
    else:
        db.add(CoachProfile(user_id=user.id, team_id=coach_tid, division=coach_division.strip(), conference=coach_conference.strip(), college=coach_college.strip()))
    db.commit()

    if role == "coach" and invite_token:
        inv = db.query(CoachInvite).filter(CoachInvite.token == invite_token).first()
        if inv:
            inv.used = True
            inv.used_by = user.id
            db.commit()
    # Session rotation: clear old session and set fresh data to prevent fixation
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["is_admin"] = bool(user.is_admin)
    request.session["role"] = user.role
    request.session["subscription_tier"] = user.subscription_tier or "free"
    request.session["session_version"] = user.session_version or 0
    if role == "player":
        import asyncio
        asyncio.create_task(send_player_signup_notification(user.username, user.email, school_name.strip()))

        # Check for in-person payment bypass token (open, untied, not yet used)
        if bypass_token:
            brec = db.query(InPersonPaymentToken).filter(
                InPersonPaymentToken.token == bypass_token,
                InPersonPaymentToken.used_at == None,
                InPersonPaymentToken.user_id == None,
            ).first()
            if brec and brec.expires_at > datetime.utcnow():
                user.subscription_tier = "premium"
                user.in_person_paid_until = datetime(2027, 3, 26)
                brec.used_at = datetime.utcnow()
                brec.user_id = user.id
                db.commit()
                request.session["subscription_tier"] = "premium"
                return RedirectResponse("/dashboard?activated=1", status_code=302)

        # Create Stripe customer and checkout session immediately
        _price_map = STRIPE_PRICES_YEARLY if billing == "yearly" else STRIPE_PRICES
        _tier = tier if tier in _price_map and _price_map[tier] else "essentials"
        if _tier not in _price_map or not _price_map[_tier]:
            _price_map = STRIPE_PRICES
        try:
            customer = stripe.Customer.create(
                email=user.email, name=user.username,
                metadata={"user_id": str(user.id)}
            )
            user.stripe_customer_id = customer.id
            db.commit()
            site_url = os.environ.get("SITE_URL", "https://caprecruiting.com")
            session = stripe.checkout.Session.create(
                customer=customer.id,
                payment_method_types=["card"],
                line_items=[{"price": _price_map[_tier], "quantity": 1}],
                mode="subscription",
                success_url=f"{site_url}/upgrade/success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{site_url}/pricing",
                metadata={"user_id": str(user.id), "tier": _tier},
                subscription_data={"metadata": {"user_id": str(user.id), "tier": _tier}},
            )
            return RedirectResponse(session.url, status_code=302)
        except Exception:
            return RedirectResponse("/upgrade", status_code=302)
    return RedirectResponse("/profile/edit", status_code=302)

async def send_reset_email(to_email: str, reset_url: str):
    import aiosmtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Reset your Bearcats Recruiting password"
    msg["From"] = f"Bearcats Recruiting <{SMTP_USER}>"
    msg["To"] = to_email
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;">
        <h2 style="color:#0a1628;">Reset Your Password</h2>
        <p>We received a request to reset your password. Click the button below to choose a new one.</p>
        <p style="margin:28px 0;">
            <a href="{reset_url}" style="background:#0a1628;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px;">Reset Password</a>
        </p>
        <p style="color:#888;font-size:13px;">This link expires in 1 hour. If you didn't request this, you can ignore this email.</p>
        <p style="color:#bbb;font-size:12px;">Or copy this link: {reset_url}</p>
    </div>"""
    msg.attach(MIMEText(html, "html"))
    try:
        await aiosmtplib.send(msg, hostname=SMTP_HOST, port=SMTP_PORT, username=SMTP_USER, password=SMTP_PASSWORD, start_tls=True)
    except Exception as e:
        _logger.warning("Email send error: %s", type(e).__name__)

async def send_player_signup_notification(player_username: str, player_email: str, school: str):
    try:
        import aiosmtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        # Get all admin emails
        db = SessionLocal()
        try:
            admins = db.query(User).filter(User.is_admin == True).all()
            admin_emails = [a.email for a in admins if a.email]
        finally:
            db.close()
        if not admin_emails:
            admin_emails = [SMTP_USER]
        site_url = os.environ.get("SITE_URL", "https://caprecruiting.com")
        for admin_email in admin_emails:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"New Player Signup: {player_username}"
            msg["From"] = f"CAP Recruiting <{SMTP_USER}>"
            msg["To"] = admin_email
            html = f"""
            <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;">
                <h2 style="color:#0a1628;">New Player Signed Up</h2>
                <table style="width:100%;border-collapse:collapse;margin:16px 0;">
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">Username</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{player_username}</td></tr>
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">Email</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{player_email}</td></tr>
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">School</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{school or "—"}</td></tr>
                </table>
                <a href="{site_url}/profile/{player_username}" style="background:#0a1628;color:#f0b429;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;font-size:14px;">View Profile</a>
            </div>
            """
            msg.attach(MIMEText(html, "html"))
            await aiosmtplib.send(msg, hostname=SMTP_HOST, port=SMTP_PORT, username=SMTP_USER, password=SMTP_PASSWORD, start_tls=True)
    except Exception:
        pass  # Don't fail signup if email fails


@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_get(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": False, "error": None})

@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password_post(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    email = (form.get("email") or "").strip().lower()
    user = db.query(User).filter(User.email == email).first()
    # Always do the same work to prevent timing-based email enumeration
    import secrets as _secrets
    _dummy_token = _secrets.token_urlsafe(32)
    _dummy_url = f"{SITE_URL}/reset-password/{_dummy_token}"
    if user:
        token_str = _secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=1)
        db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id, PasswordResetToken.used == 0).delete()
        db.add(PasswordResetToken(user_id=user.id, token=token_str, expires_at=expires))
        db.commit()
        reset_url = f"{SITE_URL}/reset-password/{token_str}"
        await send_reset_email(email, reset_url)
    else:
        # Burn roughly the same time as a real email send to prevent timing leaks
        await asyncio.sleep(0.5)
    return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": True, "error": None})

@app.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_get(token: str, request: Request, db: Session = Depends(get_db)):
    rec = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == token,
        PasswordResetToken.used == 0,
        PasswordResetToken.expires_at > datetime.utcnow()
    ).first()
    if not rec:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "invalid": True, "success": False, "error": None})
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "invalid": False, "success": False, "error": None})

@app.post("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_post(token: str, request: Request, db: Session = Depends(get_db)):
    rec = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == token,
        PasswordResetToken.used == 0,
        PasswordResetToken.expires_at > datetime.utcnow()
    ).first()
    if not rec:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "invalid": True, "success": False, "error": None})
    form = await request.form()
    password = form.get("password", "")
    confirm = form.get("confirm", "")
    pw_err = validate_password_strength(password)
    if pw_err:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "invalid": False, "success": False, "error": pw_err})
    if password != confirm:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "invalid": False, "success": False, "error": "Passwords do not match."})
    user = db.query(User).filter(User.id == rec.user_id).first()
    user.password_hash = hash_password(password)
    rec.used = 1
    db.commit()
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "invalid": False, "success": True, "error": None})

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    client_ip = request.headers.get("x-real-ip", request.client.host if request.client else "unknown")
    if check_login_lockout(db, client_ip):
        return templates.TemplateResponse("login.html", {"request": request, "error": f"Too many failed attempts. Please try again in {LOGIN_LOCKOUT_MINUTES} minutes."})
    user = db.query(User).filter((User.username == username) | (User.email == username)).first()
    if not user or not verify_password(password, user.password_hash):
        record_login_attempt(db, client_ip, username, False)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password."})
    record_login_attempt(db, client_ip, username, True)
    # Session rotation: clear old session and set fresh data to prevent fixation
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["is_admin"] = bool(user.is_admin)
    request.session["role"] = user.role
    request.session["subscription_tier"] = user.subscription_tier or "free"
    return RedirectResponse("/dashboard", status_code=302)

@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=302)


@app.post("/account/logout-all")
async def logout_all_sessions(request: Request, db: Session = Depends(get_db)):
    """Invalidate all other sessions by bumping session_version."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse("/login", status_code=302)
    user.session_version = (user.session_version or 0) + 1
    db.commit()
    # Update current session to new version so we stay logged in
    request.session["session_version"] = user.session_version
    return RedirectResponse("/profile/edit?success=1", status_code=302)

# Keep GET as fallback for direct URL visits
@app.get("/logout")
async def logout_get(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, school: Optional[str] = None, year: Optional[str] = None, position: Optional[str] = None, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None

    # Get distinct schools that have registered players
    school_rows = (
        db.query(PlayerProfile.school)
        .join(User, User.id == PlayerProfile.user_id)
        .filter(User.role == "player", PlayerProfile.school != "", PlayerProfile.school != None)
        .distinct()
        .order_by(PlayerProfile.school)
        .all()
    )
    schools = [r[0] for r in school_rows]

    # Get distinct positions
    position_rows = (
        db.query(PlayerProfile.position)
        .join(User, User.id == PlayerProfile.user_id)
        .filter(User.role == "player", PlayerProfile.position != "", PlayerProfile.position != None)
        .distinct()
        .order_by(PlayerProfile.position)
        .all()
    )
    positions = [r[0] for r in position_rows]

    # Filter players
    query = db.query(User).join(PlayerProfile, User.id == PlayerProfile.user_id).filter(User.role == "player")
    if school:
        query = query.filter(PlayerProfile.school == school)
    if position:
        query = query.filter(PlayerProfile.position == position)
    player_users = query.all()

    player_data = []
    for p in player_users:
        prof = db.query(PlayerProfile).filter(PlayerProfile.user_id == p.id).first()
        if not year or (prof and prof.year == year):
            counts = _offer_div_counts(prof)
            player_data.append({"user": p, "profile": prof, "tier": p.subscription_tier or "free", "_d1": counts["D1"], "_d2": counts["D2"], "_d3": counts["D3"]})
    player_data.sort(key=lambda x: (-x["_d1"], -x["_d2"], -x["_d3"]))

    unread_count = unread_sender_count(db, user_id) if user_id else 0
    can_click_profiles = bool(user is not None)
    can_message_from_dashboard = bool(user and (user.role == "coach" or user.is_admin))
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "player_data": player_data,
        "unread_count": unread_count,
        "schools": schools,
        "positions": positions,
        "active_school": school,
        "active_year": year,
        "active_position": position,
        "can_click_profiles": can_click_profiles,
        "can_message_from_dashboard": can_message_from_dashboard,
    })

@app.get("/profile/edit", response_class=HTMLResponse)
async def edit_profile_get(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if user.role == "player":
        profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
    else:
        profile = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
    teams = db.query(Team).order_by(Team.name).all()
    videos = db.query(Video).filter(Video.user_id == user_id).order_by(Video.is_pinned.desc(), Video.created_at.desc()).all()
    transcripts = db.query(Transcript).filter(Transcript.user_id == user_id).order_by(Transcript.created_at.desc()).all() if user.role == "player" else []
    video_error = request.query_params.get("video_error")
    transcript_error = request.query_params.get("transcript_error")
    success = request.query_params.get("success") == "1"
    image_list = db.query(ProfileImage).filter(ProfileImage.user_id == user_id).order_by(ProfileImage.is_pinned.desc(), ProfileImage.created_at.desc()).all() if user.role == "player" else []
    return templates.TemplateResponse("edit_profile.html", {"request": request, "user": user, "profile": profile, "success": success, "teams": teams, "videos": videos, "video_error": video_error, "transcripts": transcripts, "transcript_error": transcript_error, "image_list": image_list})

@app.post("/profile/edit", response_class=HTMLResponse)
async def edit_profile_post(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    form = await request.form()

    if user.role == "player":
        p = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
        p.first_name = form.get("first_name", "")[:100]
        p.last_name = form.get("last_name", "")[:100]
        p.position = form.get("position", "")[:100]
        p.year = form.get("year", "")[:100]
        p.height = form.get("height", "")[:100]
        p.weight = form.get("weight", "")[:100]
        p.forty_yard = form.get("forty_yard", "")[:100]
        p.bench_press = form.get("bench_press", "")[:100]
        p.vertical = form.get("vertical", "")[:100]
        p.squat = form.get("squat", "")[:100]
        p.clean = form.get("clean", "")[:100]
        _bj_ft = form.get("broad_jump_feet", "").strip()
        _bj_in = form.get("broad_jump_inches", "").strip()
        if _bj_ft or _bj_in:
            p.broad_jump = str(_bj_ft or 0) + "'" + str(_bj_in or 0) + '"'
        else:
            p.broad_jump = ""
        p.pro_agility = form.get("pro_agility", "")[:100]
        p.wingspan = form.get("wingspan", "")[:100]
        p.gpa = form.get("gpa", "")[:100]
        p.school = form.get("school", "")[:100]
        p.city = form.get("school_city", "")[:100]
        p.state = form.get("school_state", "")[:10]
        p.bio = form.get("bio", "")[:2000]
        p.link1_label = form.get("link1_label", "")[:100]
        p.link1_url = form.get("link1_url", "")[:500]
        p.link2_label = form.get("link2_label", "")[:100]
        p.link2_url = form.get("link2_url", "")[:500]
        p.link3_label = form.get("link3_label", "")[:100]
        p.link3_url = form.get("link3_url", "")[:500]
        p.offer1 = form.get("offer1", "")[:100]
        p.offer2 = form.get("offer2", "")[:100]
        p.offer3 = form.get("offer3", "")[:100]
        p.offer4 = form.get("offer4", "")[:100]
        p.offer5 = form.get("offer5", "")[:100]
        for i in range(1, 6):
            setattr(p, f"visit{i}_school", form.get(f"visit{i}_school", "")[:200])
            setattr(p, f"visit{i}_date",   form.get(f"visit{i}_date",   "")[:50])
        p.hudl_url = form.get("hudl_url", "")[:100]
        p.x_url = form.get("x_url", "")[:100]
        p.instagram_url = form.get("instagram_url", "")[:100]
        p.phone = form.get("phone", "")[:100]
        p.contact_email = form.get("contact_email", "")[:100]
        p.intended_major = form.get("intended_major", "")[:100]
    else:
        c = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
        c.first_name = form.get("first_name", "")[:100]
        c.last_name = form.get("last_name", "")[:100]
        c.school = form.get("school", "")[:100]
        c.title = form.get("title", "")[:100]
        c.division = form.get("division", "")[:100]
        c.conference = form.get("conference", "")[:100]
        c.bio = form.get("bio", "")[:2000]
        c.link1_label = form.get("link1_label", "")[:100]
        c.link1_url = form.get("link1_url", "")[:500]
        c.link2_label = form.get("link2_label", "")[:100]
        c.link2_url = form.get("link2_url", "")[:500]
        c.phone = form.get("phone", "")[:100]
        c.contact_email = form.get("contact_email", "")[:100]
    db.commit()

    if user.role == "player":
        profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
    else:
        profile = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
    teams = db.query(Team).order_by(Team.name).all()
    videos = db.query(Video).filter(Video.user_id == user_id).order_by(Video.is_pinned.desc(), Video.created_at.desc()).all()
    transcripts = db.query(Transcript).filter(Transcript.user_id == user_id).order_by(Transcript.created_at.desc()).all() if user.role == "player" else []
    image_list = db.query(ProfileImage).filter(ProfileImage.user_id == user_id).order_by(ProfileImage.is_pinned.desc(), ProfileImage.created_at.desc()).all() if user.role == "player" else []
    return templates.TemplateResponse("edit_profile.html", {"request": request, "user": user, "profile": profile, "success": True, "teams": teams, "videos": videos, "video_error": None, "transcripts": transcripts, "transcript_error": None, "image_list": image_list})

@app.get("/profile/{username}", response_class=HTMLResponse)
async def view_profile(username: str, request: Request, db: Session = Depends(get_db)):
    current_user_id = request.session.get("user_id")
    current_user = db.query(User).filter(User.id == current_user_id).first() if current_user_id else None
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="Profile not found")

    if target.role == "player":
        profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == target.id).first()
    else:
        profile = db.query(CoachProfile).filter(CoachProfile.user_id == target.id).first()

    all_vids = db.query(Video).filter(Video.user_id == target.id).order_by(
        Video.is_pinned.desc(), Video.created_at.desc()
    ).limit(6).all()
    videos = all_vids[:5]
    has_more_videos = len(all_vids) > 5
    total_video_count = db.query(Video).filter(Video.user_id == target.id).count() if has_more_videos else len(videos)

    is_owner = bool(current_user and current_user.id == target.id)
    video_error = request.query_params.get("video_error")

    # Profile Images — visible to everyone
    image_list = db.query(ProfileImage).filter(ProfileImage.user_id == target.id).order_by(ProfileImage.is_pinned.desc(), ProfileImage.created_at.desc()).all() if target.role == "player" else []

    # Transcripts — only coaches can see; players never see their own
    transcript_list = []
    can_see_transcripts = False
    if target.role == "player" and current_user and (current_user.role == "coach" or current_user.is_admin):
        can_see_transcripts = True
        transcript_list = db.query(Transcript).filter(Transcript.user_id == target.id).order_by(Transcript.created_at.desc()).all()

    # Evaluations — only coaches/admins can see/write; players never see their own evals
    eval_list = []
    can_evaluate = False
    if target.role == "player" and current_user and (current_user.role == "coach" or current_user.is_admin):
        can_evaluate = True
        raw_evals = (
            db.query(Evaluation, User)
            .join(User, Evaluation.coach_id == User.id)
            .filter(Evaluation.player_id == target.id)
            .order_by(Evaluation.created_at.desc())
            .limit(5)
            .all()
        )
        for ev, coach_user in raw_evals:
            cp = db.query(CoachProfile).filter(CoachProfile.user_id == coach_user.id).first()
            coach_name = f"{cp.first_name} {cp.last_name}".strip() if cp and (cp.first_name or cp.last_name) else coach_user.username
            fmt_date = ev.created_at.strftime("%B %d, %Y") if ev.created_at else ""
            eval_list.append({"coach_name": coach_name, "date": fmt_date, "content": decrypt_message(ev.content)})

    # Build visit list — only expose school data to logged-in users
    has_visits = False
    visit_list = []
    if target.role == "player" and profile:
        for i in range(1, 6):
            school = getattr(profile, f"visit{i}_school", "") or ""
            if school:
                has_visits = True
                if current_user:
                    date_str = getattr(profile, f"visit{i}_date", "") or ""
                    try:
                        from datetime import datetime, timedelta as _dt
                        fmt_date = _dt.strptime(date_str, "%Y-%m-%d").strftime("%B %d, %Y") if date_str else ""
                    except Exception:
                        fmt_date = date_str
                    visit_list.append({"school": school, "date": fmt_date})

    unread_count = unread_sender_count(db, current_user_id) if current_user_id else 0
    pt = player_tier(target)  # gating is based on the PLAYER's paid tier
    is_admin_viewer = bool(current_user and current_user.is_admin)
    can_view_photos   = is_owner or is_admin_viewer or tier_gte(pt, "advanced")
    can_view_offers   = is_owner or is_admin_viewer or tier_gte(pt, "advanced")
    can_view_visits   = is_owner or is_admin_viewer or tier_gte(pt, "advanced")
    can_view_videos   = is_owner or is_admin_viewer or tier_gte(pt, "premium")
    can_view_contact  = is_owner or is_admin_viewer or tier_gte(pt, "premium")
    can_message       = bool(not is_owner and (is_admin_viewer or (current_user and current_user.role == "coach" and tier_gte(pt, "premium"))))
    # Transcripts: only coaches can view; requires player to be advanced+
    if not (is_owner or is_admin_viewer or (current_user and current_user.role == "coach" and tier_gte(pt, "advanced"))):
        can_see_transcripts = False
        transcript_list = []
    if not can_view_photos:
        image_list = []
    if not can_view_visits:
        visit_list = []
        has_visits = False
    if not can_view_videos:
        videos = []
        has_more_videos = False
        total_video_count = 0
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "target": target,
        "profile": profile,
        "current_user": current_user,
        "unread_count": unread_count,
        "videos": videos,
        "has_more_videos": has_more_videos,
        "total_video_count": total_video_count,
        "is_owner": is_owner,
        "video_error": video_error,
        "visit_list": visit_list,
        "has_visits": has_visits,
        "eval_list": eval_list,
        "can_evaluate": can_evaluate,
        "image_list": image_list,
        "transcript_list": transcript_list,
        "can_see_transcripts": can_see_transcripts,
        "viewer_tier": pt,
        "can_view_photos": can_view_photos,
        "can_view_offers": can_view_offers,
        "can_view_visits": can_view_visits,
        "can_view_videos": can_view_videos,
        "can_view_contact": can_view_contact,
        "can_message": can_message,
    })

@app.get("/videos/{username}", response_class=HTMLResponse)
async def all_videos(username: str, request: Request, db: Session = Depends(get_db)):
    current_user_id = request.session.get("user_id")
    current_user = db.query(User).filter(User.id == current_user_id).first() if current_user_id else None
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.role == "player":
        target_profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == target.id).first()
    else:
        target_profile = db.query(CoachProfile).filter(CoachProfile.user_id == target.id).first()
    videos = db.query(Video).filter(Video.user_id == target.id).order_by(
        Video.is_pinned.desc(), Video.created_at.desc()
    ).all()
    unread_count = unread_sender_count(db, current_user_id) if current_user_id else 0
    is_owner = bool(current_user and current_user.id == target.id)
    video_error = request.query_params.get("video_error")
    return templates.TemplateResponse("videos.html", {
        "request": request,
        "target": target,
        "target_profile": target_profile,
        "videos": videos,
        "current_user": current_user,
        "unread_count": unread_count,
        "is_owner": is_owner,
        "video_error": video_error,
    })

@app.post("/profile/videos/upload")
async def upload_video(
    request: Request,
    video: UploadFile = File(...),
    title: str = Form(""),
    redirect_to: str = Form("/profile/edit"),
    target_user_id: str = Form(default=""),
    db: Session = Depends(get_db)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    redirect_to = _safe_redirect(redirect_to, "/profile/edit")
    logged_in = db.query(User).filter(User.id == user_id).first()

    # Allow admin to upload video for another user
    if target_user_id.strip().isdigit() and logged_in and logged_in.is_admin:
        upload_user_id = int(target_user_id.strip())
    else:
        upload_user_id = user_id

    ext = video.filename.rsplit(".", 1)[-1].lower() if "." in video.filename else ""
    if ext not in VIDEO_ALLOWED_EXTENSIONS:
        return RedirectResponse(redirect_to + "?video_error=type", status_code=302)
    # File size check - enforce VIDEO_MAX_BYTES at app level
    _video_header = await video.read(512)
    cl = request.headers.get("content-length")
    if cl and int(cl) > VIDEO_MAX_BYTES:
        return RedirectResponse(redirect_to + "?video_error=size", status_code=302)
    await video.seek(0)
    try:
        import magic as _magic
        _detected = _magic.from_buffer(_video_header, mime=True)
        if not _detected.startswith("video/"):
            return RedirectResponse(redirect_to + "?video_error=type", status_code=302)
    except Exception:
        pass

    key = f"videos/{upload_user_id}/{uuid.uuid4().hex}.{ext}"
    content_type = video.content_type or f"video/{ext}"
    file_data = video.file
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: s3.upload_fileobj(
                file_data,
                SPACES_BUCKET,
                key,
                ExtraArgs={"ContentType": content_type}
            )
        )
    except Exception:
        return RedirectResponse(redirect_to + "?video_error=upload", status_code=302)

    video_url = f"{SPACES_BASE_URL}/{key}"
    db.add(Video(user_id=upload_user_id, title=title.strip(), url=video_url, embed_url=video_url, thumbnail_url=""))
    db.commit()
    sep = "&" if "?" in redirect_to else "?"
    return RedirectResponse(redirect_to + sep + "success=1", status_code=302)

@app.post("/profile/videos/{video_id}/pin")
async def pin_video(video_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    video = db.query(Video).filter(Video.id == video_id, Video.user_id == user_id).first()
    if not video:
        raise HTTPException(status_code=404)
    user = db.query(User).filter(User.id == user_id).first()
    form = await request.form()
    redirect_to = _safe_redirect(form.get("redirect_to", f"/profile/{user.username}"), f"/profile/{user.username}")
    if video.is_pinned:
        video.is_pinned = False
    else:
        db.query(Video).filter(Video.user_id == user_id).update({"is_pinned": False})
        video.is_pinned = True
    db.commit()
    return RedirectResponse(redirect_to, status_code=302)

@app.post("/profile/videos/{video_id}/delete")
async def delete_video(video_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    logged_in = db.query(User).filter(User.id == user_id).first()
    video = db.query(Video).filter(Video.id == video_id).first()
    if not video:
        raise HTTPException(status_code=404)
    # Only owner or admin can delete
    if video.user_id != user_id and not (logged_in and logged_in.is_admin):
        raise HTTPException(status_code=403)
    form = await request.form()
    redirect_to = _safe_redirect(form.get("redirect_to", f"/profile/{logged_in.username}"), f"/profile/{logged_in.username}")
    # Delete file from Spaces
    try:
        key = video.url.replace(f"{SPACES_BASE_URL}/", "")
        s3.delete_object(Bucket=SPACES_BUCKET, Key=key)
    except Exception:
        pass
    db.delete(video)
    db.commit()
    sep = "&" if "?" in redirect_to else "?"
    return RedirectResponse(redirect_to + sep + "success=1", status_code=302)

@app.post("/profile/images/upload")
async def upload_profile_image(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    uploader = db.query(User).filter(User.id == user_id).first()
    if not uploader:
        return RedirectResponse("/login", status_code=302)

    form = await request.form()
    redirect_to = _safe_redirect(str(form.get("redirect_to", "")), "/profile/edit")
    back = redirect_to

    # Determine target user
    target_user_id = user_id
    if uploader.is_admin and redirect_to:
        import re as _re
        m = _re.search(r"/admin/users/(\d+)/", redirect_to)
        if m:
            target_user_id = int(m.group(1))
        else:
            m2 = _re.search(r"/profile/([^/?]+)", redirect_to)
            if m2:
                tu = db.query(User).filter(User.username == m2.group(1)).first()
                if tu:
                    target_user_id = tu.id

    images = form.getlist("image")
    if not images:
        single = form.get("image")
        images = [single] if single else []
    images = [f for f in images if f and hasattr(f, "filename") and f.filename]

    import io as _io
    from PIL import Image as _Image

    for image in images:
        count = db.query(ProfileImage).filter(ProfileImage.user_id == target_user_id).count()
        if count >= IMAGE_MAX_COUNT:
            break
        ext = image.filename.rsplit(".", 1)[-1].lower() if "." in image.filename else ""
        if ext not in IMAGE_ALLOWED_EXTENSIONS:
            continue
        contents = await image.read()
        if len(contents) > IMAGE_MAX_BYTES:
            continue

        # Resize to max 1200px on longest side, convert to JPEG for efficiency
        try:
            img = _Image.open(_io.BytesIO(contents))
            from PIL import ImageOps as _ImageOps
            img = _ImageOps.exif_transpose(img)
            img = img.convert("RGB")
            img.thumbnail((1200, 1200), _Image.LANCZOS)
            buf = _io.BytesIO()
            img.save(buf, format="JPEG", quality=82, optimize=True)
            buf.seek(0)
            upload_bytes = buf
            content_type = "image/jpeg"
            save_ext = "jpg"
        except Exception:
            upload_bytes = _io.BytesIO(contents)
            content_type = IMAGE_CONTENT_TYPES.get(ext, "image/jpeg")
            save_ext = ext

        key = f"profile-images/{target_user_id}/{uuid.uuid4().hex}.{save_ext}"
        try:
            s3.upload_fileobj(
                upload_bytes, SPACES_BUCKET, key,
                ExtraArgs={"ContentType": content_type, "ACL": "public-read"}
            )
            db.add(ProfileImage(user_id=target_user_id, file_url=f"{SPACES_BASE_URL}/{key}"))
        except Exception:
            continue
    db.commit()
    return RedirectResponse(back, status_code=302)


@app.post("/profile/images/{image_id}/delete")
async def delete_profile_image(image_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    current_user = db.query(User).filter(User.id == user_id).first()
    if current_user and current_user.is_admin:
        img = db.query(ProfileImage).filter(ProfileImage.id == image_id).first()
    else:
        img = db.query(ProfileImage).filter(ProfileImage.id == image_id, ProfileImage.user_id == user_id).first()
    if not img:
        raise HTTPException(status_code=404)
    form = await request.form()
    redirect_to = _safe_redirect(form.get("redirect_to", "/profile/edit"), "/profile/edit")
    try:
        key = img.file_url.replace(f"{SPACES_BASE_URL}/", "")
        s3.delete_object(Bucket=SPACES_BUCKET, Key=key)
    except Exception:
        pass
    db.delete(img)
    db.commit()
    return RedirectResponse(redirect_to, status_code=302)

@app.post("/profile/transcripts/upload")
async def upload_transcript(
    request: Request,
    transcript: UploadFile = File(...),
    title: str = Form(""),
    redirect_to: str = Form("/profile/edit"),
    db: Session = Depends(get_db)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    redirect_to = _safe_redirect(redirect_to, "/profile/edit")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or (user.role != "player" and not user.is_admin):
        raise HTTPException(status_code=403, detail="Only players or admins can upload transcripts.")

    target_user_id = user_id
    if user.is_admin:
        import re as _re
        m = _re.search(r"/admin/users/(\d+)/", str(redirect_to))
        if m:
            target_user_id = int(m.group(1))

    count = db.query(Transcript).filter(Transcript.user_id == target_user_id).count()
    if count >= TRANSCRIPT_MAX_COUNT:
        return RedirectResponse(redirect_to + "?transcript_error=limit", status_code=302)

    ext = transcript.filename.rsplit(".", 1)[-1].lower() if "." in transcript.filename else ""
    if ext not in TRANSCRIPT_ALLOWED_EXTENSIONS:
        return RedirectResponse(redirect_to + "?transcript_error=type", status_code=302)

    contents = await transcript.read()
    if len(contents) > TRANSCRIPT_MAX_BYTES:
        return RedirectResponse(redirect_to + "?transcript_error=size", status_code=302)
    # Magic byte check — reject if magic detects wrong type, allow if magic unavailable
    try:
        import magic as _magic
        _detected = _magic.from_buffer(contents[:512], mime=True)
        _allowed_mimes = {"application/pdf", "application/msword",
                          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                          "application/octet-stream"}
        if _detected not in _allowed_mimes:
            return RedirectResponse(redirect_to + "?transcript_error=type", status_code=302)
    except ImportError:
        pass  # magic not installed — allow based on extension only

    import io
    key = f"transcripts/{target_user_id}/{uuid.uuid4().hex}.{ext}"
    try:
        s3.upload_fileobj(
            io.BytesIO(contents),
            SPACES_BUCKET,
            key,
            ExtraArgs={"ContentType": TRANSCRIPT_CONTENT_TYPES.get(ext, "application/octet-stream")}
        )
    except Exception:
        return RedirectResponse(redirect_to + "?transcript_error=upload", status_code=302)

    file_url = f"{SPACES_BASE_URL}/{key}"
    t_title = title.strip() or transcript.filename
    db.add(Transcript(user_id=target_user_id, title=t_title, file_url=file_url, filename=transcript.filename))
    db.commit()
    return RedirectResponse(redirect_to, status_code=302)

@app.post("/profile/transcripts/{transcript_id}/delete")
async def delete_transcript(transcript_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    current_user = db.query(User).filter(User.id == user_id).first()
    if current_user and current_user.is_admin:
        t = db.query(Transcript).filter(Transcript.id == transcript_id).first()
    else:
        t = db.query(Transcript).filter(Transcript.id == transcript_id, Transcript.user_id == user_id).first()
    if not t:
        raise HTTPException(status_code=404)
    form = await request.form()
    redirect_to = _safe_redirect(form.get("redirect_to", "/profile/edit"), "/profile/edit")
    try:
        key = t.file_url.replace(f"{SPACES_BASE_URL}/", "")
        s3.delete_object(Bucket=SPACES_BUCKET, Key=key)
    except Exception:
        pass
    db.delete(t)
    db.commit()
    return RedirectResponse(redirect_to, status_code=302)

@app.get("/profile/transcripts/{transcript_id}/download")
async def download_transcript(transcript_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    current_user = db.query(User).filter(User.id == user_id).first()
    if not current_user:
        return RedirectResponse("/login", status_code=302)
    t = db.query(Transcript).filter(Transcript.id == transcript_id).first()
    if not t:
        raise HTTPException(status_code=404)
    transcript_owner = db.query(User).filter(User.id == t.user_id).first()
    _pt = player_tier(transcript_owner)
    if current_user.id != t.user_id and not current_user.is_admin:
        if current_user.role != "coach" or not tier_gte(_pt, "advanced"):
            raise HTTPException(status_code=403, detail="Player must be on Advanced plan or higher")
    key = t.file_url.replace(f"{SPACES_BASE_URL}/", "")
    obj = s3.get_object(Bucket=SPACES_BUCKET, Key=key)
    ext = key.rsplit(".", 1)[-1].lower() if "." in key else "pdf"
    filename = t.filename or f"transcript.{ext}"
    content_type = TRANSCRIPT_CONTENT_TYPES.get(ext, "application/octet-stream")
    from urllib.parse import quote
    return Response(
        content=obj["Body"].read(),
        media_type=content_type,
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"}
    )

@app.get("/profile/transcripts/{transcript_id}/view", response_class=HTMLResponse)
async def view_transcript(transcript_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    current_user = db.query(User).filter(User.id == user_id).first()
    if not current_user:
        return RedirectResponse("/login", status_code=302)
    t = db.query(Transcript).filter(Transcript.id == transcript_id).first()
    if not t:
        raise HTTPException(status_code=404)
    transcript_owner2 = db.query(User).filter(User.id == t.user_id).first()
    _pt2 = player_tier(transcript_owner2)
    if current_user.id != t.user_id and not current_user.is_admin:
        if current_user.role != "coach" or not tier_gte(_pt2, "advanced"):
            raise HTTPException(status_code=403, detail="Player must be on Advanced plan or higher")
    ext = t.file_url.split("?")[0].rsplit(".", 1)[-1].lower() if "." in t.file_url else "pdf"
    # Generate presigned URL (valid 1 hour) so private objects are viewable
    _key = t.file_url.replace(f"{SPACES_BASE_URL}/", "")
    try:
        presigned_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": SPACES_BUCKET, "Key": _key},
            ExpiresIn=600  # 10 minutes
        )
    except Exception:
        presigned_url = t.file_url
    if ext == "pdf":
        viewer_url = presigned_url
    else:
        # Non-PDF: redirect to download instead of leaking presigned URL to Google
        return RedirectResponse(f"/profile/transcripts/{transcript_id}/download", status_code=302)
    from html import escape as _escape
    title = t.title or t.filename or "Transcript"
    safe_title = _escape(title)
    safe_viewer_url = _escape(viewer_url)
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset='UTF-8'>
  <meta http-equiv='Content-Security-Policy' content="default-src 'none'; style-src 'unsafe-inline'; frame-src https: blob:; connect-src 'self';">
  <title>{safe_title}</title>
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ display:flex; flex-direction:column; height:100vh; font-family:sans-serif; background:#f5f5f5; }}
    .toolbar {{ display:flex; align-items:center; justify-content:space-between; padding:10px 16px; background:#1e3a5f; color:#fff; flex-shrink:0; }}
    .toolbar h2 {{ font-size:15px; font-weight:600; }}
    .toolbar a {{ color:#fff; text-decoration:none; font-size:13px; background:rgba(255,255,255,0.15); padding:6px 12px; border-radius:6px; }}
    iframe {{ flex:1; border:none; width:100%; }}
  </style>
</head>
<body>
  <div class='toolbar'>
    <h2>{safe_title}</h2>
    <a href='/profile/transcripts/{transcript_id}/download'>Download</a>
  </div>
  <iframe src='{safe_viewer_url}'></iframe>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.post("/profile/{username}/evaluate")
async def submit_evaluation(username: str, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    coach = db.query(User).filter(User.id == user_id).first()
    if not coach or (coach.role != "coach" and not coach.is_admin):
        raise HTTPException(status_code=403, detail="Only coaches or admins can submit evaluations.")
    player = db.query(User).filter(User.username == username).first()
    if not player or player.role != "player":
        raise HTTPException(status_code=404)
    form = await request.form()
    content = (form.get("content") or "").strip()[:5000]
    if content:
        db.add(Evaluation(player_id=player.id, coach_id=coach.id, content=encrypt_message(content)))
        db.commit()
    return RedirectResponse(f"/profile/{username}", status_code=302)

@app.post("/admin/users/{target_id}/set-stars", response_class=HTMLResponse)
async def admin_set_stars(target_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    form = await request.form()
    stars = int(form.get("stars", 0))
    stars = max(0, min(5, stars))
    profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == target_id).first()
    if profile:
        old_stars = profile.stars
        profile.stars = stars
        db.commit()
        _ip = request.headers.get("x-real-ip", request.client.host if request.client else "")
        log_admin_action(db, admin.id, "set_stars", target_id, f"old={old_stars} new={stars}", _ip)
    target = db.query(User).filter(User.id == target_id).first()
    if target:
        return RedirectResponse(f"/profile/{target.username}", status_code=302)
    return RedirectResponse("/dashboard", status_code=302)

@app.post("/admin/users/{target_id}/set-tier", response_class=HTMLResponse)
async def admin_set_tier(target_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    form = await request.form()
    tier = form.get("subscription_tier", "free")
    if tier not in ("free", "essentials", "advanced", "premium"):
        tier = "free"
    target = db.query(User).filter(User.id == target_id).first()
    if target:
        old_tier = target.subscription_tier
        target.subscription_tier = tier
        db.commit()
        _ip = request.headers.get("x-real-ip", request.client.host if request.client else "")
        log_admin_action(db, admin.id, "set_tier", target_id, f"old={old_tier} new={tier}", _ip)
    return RedirectResponse(f"/admin/users/{target_id}/edit-profile", status_code=302)

@app.get("/admin/teams", response_class=HTMLResponse)
async def admin_teams_get(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    teams_raw = db.query(Team).order_by(Team.name).all()
    teams = []
    for t in teams_raw:
        count = db.query(PlayerProfile).filter(PlayerProfile.team_id == t.id).count()
        if count > 0:
            teams.append({"id": t.id, "name": t.name, "player_count": count})
    coaches_raw = db.query(User).filter(User.role == "coach").order_by(User.username).all()
    coaches = []
    for c in coaches_raw:
        cp = db.query(CoachProfile).filter(CoachProfile.user_id == c.id).first()
        coaches.append({"user": c, "profile": cp})
    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("admin_teams.html", {
        "request": request, "user": user,
        "teams": teams, "coaches": coaches, "unread_count": unread_count,
        "success": False, "error": None,
    })

@app.post("/admin/teams/create", response_class=HTMLResponse)
async def admin_teams_create(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    form = await request.form()
    name = form.get("name", "").strip()

    def render(success, error):
        teams_raw = db.query(Team).order_by(Team.name).all()
        teams = [{"id": t.id, "name": t.name, "player_count": db.query(PlayerProfile).filter(PlayerProfile.team_id == t.id).count()} for t in teams_raw]
        coaches_raw = db.query(User).filter(User.role == "coach").order_by(User.username).all()
        coaches = [{"user": c, "profile": db.query(CoachProfile).filter(CoachProfile.user_id == c.id).first()} for c in coaches_raw]
        return templates.TemplateResponse("admin_teams.html", {
            "request": request, "user": user, "teams": teams, "coaches": coaches,
            "unread_count": unread_sender_count(db, user_id), "success": success, "error": error
        })

    if not name:
        return render(False, "Team name cannot be empty.")
    if db.query(Team).filter(Team.name == name).first():
        return render(False, f'A team named "{name}" already exists.')
    db.add(Team(name=name))
    db.commit()
    return render(True, None)

@app.get("/admin/users/{target_id}/edit-profile", response_class=HTMLResponse)
async def admin_edit_profile_get(target_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == target_id).first() if target.role == "player" else db.query(CoachProfile).filter(CoachProfile.user_id == target_id).first()
    teams = db.query(Team).order_by(Team.name).all()
    videos = db.query(Video).filter(Video.user_id == target_id).order_by(Video.is_pinned.desc(), Video.created_at.desc()).all()
    transcripts = db.query(Transcript).filter(Transcript.user_id == target_id).order_by(Transcript.created_at.desc()).all() if target.role == "player" else []
    image_list = db.query(ProfileImage).filter(ProfileImage.user_id == target_id).order_by(ProfileImage.is_pinned.desc(), ProfileImage.created_at.desc()).all() if target.role == "player" else []
    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("edit_profile.html", {
        "request": request, "user": target, "profile": profile,
        "success": request.query_params.get("success") == "1", "teams": teams, "videos": videos,
        "video_error": request.query_params.get("video_error"), "transcripts": transcripts, "transcript_error": None,
        "image_list": image_list,
        "profile_form_action": f"/admin/users/{target_id}/edit-profile",
        "unread_count": unread_count,
    })

@app.post("/admin/users/{target_id}/edit-profile", response_class=HTMLResponse)
async def admin_edit_profile_post(target_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    form = await request.form()
    if target.role == "player":
        p = db.query(PlayerProfile).filter(PlayerProfile.user_id == target_id).first()
        p.first_name = form.get("first_name", "")[:100]
        p.last_name = form.get("last_name", "")[:100]
        p.position = form.get("position", "")[:100]
        p.year = form.get("year", "")[:100]
        p.height = form.get("height", "")[:100]
        p.weight = form.get("weight", "")[:100]
        p.forty_yard = form.get("forty_yard", "")[:100]
        p.bench_press = form.get("bench_press", "")[:100]
        p.vertical = form.get("vertical", "")[:100]
        p.squat = form.get("squat", "")[:100]
        p.clean = form.get("clean", "")[:100]
        _bj_ft = form.get("broad_jump_feet", "").strip()
        _bj_in = form.get("broad_jump_inches", "").strip()
        if _bj_ft or _bj_in:
            p.broad_jump = str(_bj_ft or 0) + "'" + str(_bj_in or 0) + '"'
        else:
            p.broad_jump = ""
        p.pro_agility = form.get("pro_agility", "")[:100]
        p.wingspan = form.get("wingspan", "")[:100]
        p.gpa = form.get("gpa", "")[:100]
        p.school = form.get("school", "")[:100]
        p.city = form.get("school_city", "")[:100]
        p.state = form.get("school_state", "")[:10]
        p.bio = form.get("bio", "")[:2000]
        p.hudl_url = form.get("hudl_url", "")[:100]
        p.x_url = form.get("x_url", "")[:100]
        p.instagram_url = form.get("instagram_url", "")[:100]
        p.phone = form.get("phone", "")[:100]
        p.contact_email = form.get("contact_email", "")[:100]
        p.offer1 = form.get("offer1", "")[:100]
        p.offer2 = form.get("offer2", "")[:100]
        p.offer3 = form.get("offer3", "")[:100]
        p.offer4 = form.get("offer4", "")[:100]
        p.offer5 = form.get("offer5", "")[:100]
        for i in range(1, 6):
            setattr(p, f"visit{i}_school", form.get(f"visit{i}_school", "")[:200])
            setattr(p, f"visit{i}_date", form.get(f"visit{i}_date", "")[:50])
        p.ncaa_eligibility_num = form.get("ncaa_eligibility_num", "")[:100]
        p.intended_major = form.get("intended_major", "")[:100]
    else:
        c = db.query(CoachProfile).filter(CoachProfile.user_id == target_id).first()
        c.first_name = form.get("first_name", "")[:100]
        c.last_name = form.get("last_name", "")[:100]
        c.school = form.get("school", "")[:100]
        c.title = form.get("title", "")[:100]
        c.division = form.get("division", "")[:100]
        c.conference = form.get("conference", "")[:100]
        c.bio = form.get("bio", "")[:2000]
        c.phone = form.get("phone", "")[:100]
        c.contact_email = form.get("contact_email", "")[:100]
    db.commit()
    profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == target_id).first() if target.role == "player" else db.query(CoachProfile).filter(CoachProfile.user_id == target_id).first()
    teams = db.query(Team).order_by(Team.name).all()
    videos = db.query(Video).filter(Video.user_id == target_id).order_by(Video.is_pinned.desc(), Video.created_at.desc()).all()
    transcripts = db.query(Transcript).filter(Transcript.user_id == target_id).order_by(Transcript.created_at.desc()).all() if target.role == "player" else []
    image_list = db.query(ProfileImage).filter(ProfileImage.user_id == target_id).order_by(ProfileImage.is_pinned.desc(), ProfileImage.created_at.desc()).all() if target.role == "player" else []
    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("edit_profile.html", {
        "request": request, "user": target, "profile": profile,
        "success": True, "teams": teams, "videos": videos,
        "video_error": None, "transcripts": transcripts, "transcript_error": None,
        "image_list": image_list,
        "profile_form_action": f"/admin/users/{target_id}/edit-profile",
        "unread_count": unread_count,
    })

@app.get("/admin/invites", response_class=HTMLResponse)
async def admin_invites_get(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    invites = db.query(CoachInvite).order_by(CoachInvite.created_at.desc()).all()
    used_by_users = {}
    for inv in invites:
        if inv.used_by:
            u = db.query(User).filter(User.id == inv.used_by).first()
            if u:
                used_by_users[inv.used_by] = u.username
    site_url = os.environ.get("SITE_URL", "https://caprecruiting.com")
    bypass_link = request.query_params.get("bypass_link", "")
    return templates.TemplateResponse("admin_invites.html", {
        "request": request,
        "invites": invites,
        "used_by_users": used_by_users,
        "site_url": site_url,
        "now": datetime.utcnow(),
        "bypass_link": bypass_link,
    })

@app.post("/admin/invites/create", response_class=HTMLResponse)
async def admin_invites_create(request: Request, note: str = Form(""), db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    from datetime import timedelta
    token = uuid.uuid4().hex
    inv = CoachInvite(
        token=token,
        created_by=admin.id,
        expires_at=datetime.utcnow() + timedelta(days=7),
        note=note.strip()
    )
    db.add(inv)
    db.commit()
    return RedirectResponse("/admin/invites", status_code=302)

@app.post("/admin/invites/{token}/revoke", response_class=HTMLResponse)
async def admin_invites_revoke(token: str, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    inv = db.query(CoachInvite).filter(CoachInvite.token == token).first()
    if inv and not inv.used:
        inv.expires_at = datetime.utcnow()
        db.commit()
    return RedirectResponse("/admin/invites", status_code=302)

@app.post("/admin/users/{target_id}/delete", response_class=HTMLResponse)
async def admin_delete_user(target_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404)
    if target.id == admin.id:
        return RedirectResponse("/dashboard", status_code=302)
    _ip = request.headers.get("x-real-ip", request.client.host if request.client else "")
    log_admin_action(db, admin.id, "delete_user", target_id, f"username={target.username}, role={target.role}", _ip)
    # Clean up S3 files before deleting DB records
    for vid in db.query(Video).filter(Video.user_id == target_id).all():
        try:
            key = vid.url.replace(f"{SPACES_BASE_URL}/", "")
            s3.delete_object(Bucket=SPACES_BUCKET, Key=key)
        except Exception:
            pass
    for img in db.query(ProfileImage).filter(ProfileImage.user_id == target_id).all():
        try:
            key = img.file_url.replace(f"{SPACES_BASE_URL}/", "")
            s3.delete_object(Bucket=SPACES_BUCKET, Key=key)
        except Exception:
            pass
    for tr in db.query(Transcript).filter(Transcript.user_id == target_id).all():
        try:
            key = tr.file_url.replace(f"{SPACES_BASE_URL}/", "")
            s3.delete_object(Bucket=SPACES_BUCKET, Key=key)
        except Exception:
            pass
    # Delete local profile photo if exists
    pp = db.query(PlayerProfile).filter(PlayerProfile.user_id == target_id).first()
    cp = db.query(CoachProfile).filter(CoachProfile.user_id == target_id).first()
    for prof in (pp, cp):
        if prof and hasattr(prof, "photo") and prof.photo:
            local_path = os.path.join("/home/recruiting/bearcats/static/uploads", os.path.basename(prof.photo))
            if os.path.exists(local_path):
                try:
                    os.remove(local_path)
                except Exception:
                    pass
    db.query(PlayerProfile).filter(PlayerProfile.user_id == target_id).delete()
    db.query(CoachProfile).filter(CoachProfile.user_id == target_id).delete()
    db.query(Message).filter((Message.sender_id == target_id) | (Message.receiver_id == target_id)).delete()
    db.query(Video).filter(Video.user_id == target_id).delete()
    db.query(ProfileImage).filter(ProfileImage.user_id == target_id).delete()
    db.query(Transcript).filter(Transcript.user_id == target_id).delete()
    db.query(Evaluation).filter((Evaluation.coach_id == target_id) | (Evaluation.player_id == target_id)).delete()
    db.delete(target)
    db.commit()
    return RedirectResponse("/dashboard", status_code=302)


@app.post("/admin/users/{target_id}/generate-bypass")
async def admin_generate_bypass(target_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    target = db.query(User).filter(User.id == target_id).first()
    if not target or target.role != "player":
        raise HTTPException(status_code=404, detail="Player not found.")
    import secrets as _sec
    token = _sec.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=7)
    db.add(InPersonPaymentToken(token=token, user_id=target_id, expires_at=expires_at))
    db.commit()
    site_url = os.environ.get("SITE_URL", "https://bearcatrecruiting.com")
    link = f"{site_url}/join/{token}"
    _ip = request.headers.get("x-real-ip", request.client.host if request.client else "")
    log_admin_action(db, admin.id, "generate_bypass", target_id, f"token={token[:8]}...", _ip)
    return RedirectResponse(f"/admin/users/{target_id}/edit-profile?bypass_link={link}", status_code=302)


@app.post("/admin/bypass-links/generate")
async def admin_generate_open_bypass(request: Request, db: Session = Depends(get_db)):
    """Generate an open bypass link for a new (not yet signed up) player."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    import secrets as _sec
    token = _sec.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=7)
    db.add(InPersonPaymentToken(token=token, user_id=None, expires_at=expires_at))
    db.commit()
    site_url = os.environ.get("SITE_URL", "https://bearcatrecruiting.com")
    link = f"{site_url}/join/{token}"
    return RedirectResponse(f"/admin/invites?bypass_link={link}", status_code=302)


@app.get("/messages", response_class=HTMLResponse)
async def messages_inbox(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()

    from sqlalchemy import or_

    # Single query: all messages visible to this user (not soft-deleted)
    all_msgs = db.query(Message).filter(
        or_(
            (Message.sender_id == user_id) & (Message.deleted_by_sender == False),
            (Message.receiver_id == user_id) & (Message.deleted_by_receiver == False)
        )
    ).all()

    # Collect unique peer IDs (anyone I messaged or who messaged me)
    peer_ids = set()
    for m in all_msgs:
        peer_id = m.receiver_id if m.sender_id == user_id else m.sender_id
        peer_ids.add(peer_id)

    conversations = []
    for pid in peer_ids:
        peer = db.query(User).filter(User.id == pid).first()
        if not peer:
            continue
        last_msg = db.query(Message).filter(
            or_(
                (Message.sender_id == user_id) & (Message.receiver_id == pid) & (Message.deleted_by_sender == False),
                (Message.sender_id == pid) & (Message.receiver_id == user_id) & (Message.deleted_by_receiver == False)
            )
        ).order_by(Message.timestamp.desc()).first()
        unread = db.query(Message).filter(
            Message.sender_id == pid,
            Message.receiver_id == user_id,
            Message.read == False
        ).count()
        if last_msg:
            last_msg.content = decrypt_message(last_msg.content)
        conversations.append({"peer": peer, "last_msg": last_msg, "unread": unread})

    conversations.sort(key=lambda x: x["last_msg"].timestamp if x["last_msg"] else datetime.min, reverse=True)
    total_unread = unread_sender_count(db, user_id)
    # All players for the "new message" picker (admins + coaches can message anyone)
    all_players = db.query(User).filter(User.role == "player").order_by(User.username).all()
    player_profiles_map = {}
    for p in all_players:
        prof = db.query(PlayerProfile).filter(PlayerProfile.user_id == p.id).first()
        player_profiles_map[p.id] = prof
    return templates.TemplateResponse("messages.html", {
        "request": request,
        "user": user,
        "conversations": conversations,
        "unread_count": total_unread,
        "all_players": all_players,
        "player_profiles_map": player_profiles_map,
    })

@app.get("/messages/{username}", response_class=HTMLResponse)
async def conversation_get(username: str, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    peer = db.query(User).filter(User.username == username).first()
    if not peer:
        raise HTTPException(status_code=404, detail="User not found")

    msgs = db.query(Message).filter(
        ((Message.sender_id == user_id) & (Message.receiver_id == peer.id) & (Message.deleted_by_sender == False)) |
        ((Message.sender_id == peer.id) & (Message.receiver_id == user_id) & (Message.deleted_by_receiver == False))
    ).order_by(Message.timestamp.asc()).all()

    for m in msgs:
        m.content = decrypt_message(m.content)
        if m.receiver_id == user_id and not m.read:
            m.read = True
    db.commit()

    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("conversation.html", {
        "request": request,
        "user": user,
        "peer": peer,
        "messages": msgs,
        "unread_count": unread_count
    })




@app.post("/messages/{username}/delete-thread", response_class=HTMLResponse)
async def delete_thread(username: str, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    peer = db.query(User).filter(User.username == username).first()
    if not peer:
        raise HTTPException(status_code=404)
    # Soft-delete: mark messages as deleted for the current user's side
    db.query(Message).filter(
        Message.sender_id == user_id, Message.receiver_id == peer.id
    ).update({"deleted_by_sender": True})
    db.query(Message).filter(
        Message.sender_id == peer.id, Message.receiver_id == user_id
    ).update({"deleted_by_receiver": True})
    db.commit()
    return RedirectResponse("/messages", status_code=302)


@app.post("/messages/delete-conversations", response_class=HTMLResponse)
async def delete_conversations(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    form = await request.form()
    peer_ids = form.getlist("peer_id")
    for pid_str in peer_ids:
        try:
            pid = int(pid_str)
        except ValueError:
            continue
        db.query(Message).filter(
            Message.sender_id == user_id, Message.receiver_id == pid
        ).update({"deleted_by_sender": True})
        db.query(Message).filter(
            Message.sender_id == pid, Message.receiver_id == user_id
        ).update({"deleted_by_receiver": True})
    db.commit()
    return RedirectResponse("/messages", status_code=302)


# ════════════════════════════════════════════════════════════════════════════
# LEGAL  ─ /legal
# ════════════════════════════════════════════════════════════════════════════

@app.get("/legal", response_class=HTMLResponse)
async def legal_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    contracts = (db.query(LegalContract)
                   .filter(LegalContract.hidden == False)
                   .order_by(LegalContract.created_at.desc()).all())
    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("legal.html", {
        "request": request, "user": user,
        "contracts": contracts, "unread_count": unread_count,
    })


@app.post("/legal/create", response_class=HTMLResponse)
async def legal_create(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403)
    form = await request.form()
    player_name = form.get("player_name", "").strip()
    if not player_name:
        return RedirectResponse("/legal", status_code=302)
    token = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    contract = LegalContract(token=token, player_name=player_name, created_by_id=user_id)
    db.add(contract)
    db.commit()
    db.refresh(contract)
    return RedirectResponse("/legal", status_code=302)


@app.post("/legal/{contract_id}/hide", response_class=HTMLResponse)
async def legal_hide(contract_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403)
    contract = db.query(LegalContract).filter(LegalContract.id == contract_id).first()
    if contract:
        contract.hidden = True
        db.commit()
    return RedirectResponse("/legal", status_code=302)


@app.get("/legal/docs/{filename}")
async def serve_signed_doc(filename: str, request: Request, db: Session = Depends(get_db)):
    """Serve signed PDFs — admin only."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403)
    filepath = os.path.join(SIGNED_DOCS_DIR, filename)
    # Guard against path traversal
    real_filepath = os.path.realpath(filepath)
    real_docs_dir = os.path.realpath(SIGNED_DOCS_DIR)
    if not real_filepath.startswith(real_docs_dir + os.sep):
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not os.path.exists(real_filepath):
        raise HTTPException(status_code=404)
    from fastapi.responses import FileResponse
    return FileResponse(filepath, media_type="application/pdf",
                        headers={"Content-Disposition": f"inline; filename={filename}"})


@app.get("/sign/{token}", response_class=HTMLResponse)
async def sign_page(token: str, request: Request, db: Session = Depends(get_db)):
    contract = db.query(LegalContract).filter(LegalContract.token == token).first()
    if not contract:
        raise HTTPException(status_code=404, detail="Signing link not found or has expired.")
    if contract.status == "signed":
        return templates.TemplateResponse("sign_done.html", {"request": request, "contract": contract})
    return templates.TemplateResponse("sign.html", {"request": request, "contract": contract})


@app.post("/sign/{token}", response_class=HTMLResponse)
async def sign_submit(token: str, request: Request, db: Session = Depends(get_db)):
    import fitz, base64
    contract = db.query(LegalContract).filter(LegalContract.token == token).first()
    if not contract or contract.status == "signed":
        raise HTTPException(status_code=404)
    form = await request.form()
    full_name    = form.get("full_name", "").strip()[:200]
    date_top     = form.get("date_top", "").strip()[:50]
    print_name   = form.get("print_name", "").strip()[:200]
    sign_date    = form.get("sign_date", "").strip()[:50]
    signature_data = form.get("signature_data", "").strip()

    if not signature_data or not full_name:
        return RedirectResponse(f"/sign/{token}?error=1", status_code=302)

    # Strip data URI prefix
    if "base64," in signature_data:
        signature_data = signature_data.split("base64,", 1)[1]

    # Limit signature image to 2MB decoded (base64 is ~4/3 of raw size)
    MAX_SIG_B64 = 2 * 1024 * 1024 * 4 // 3
    if len(signature_data) > MAX_SIG_B64:
        return RedirectResponse(f"/sign/{token}?error=1", status_code=302)

    sig_bytes = base64.b64decode(signature_data)

    # Validate it's actually an image before passing to PDF renderer
    try:
        import io as _io
        from PIL import Image as _PIL_Image
        _img = _PIL_Image.open(_io.BytesIO(sig_bytes))
        _img.verify()
    except Exception:
        return RedirectResponse(f"/sign/{token}?error=1", status_code=302)

    doc = fitz.open(TEMPLATE_PDF)

    # ── Page 1: overlay player name (y=131) and effective date (y=114) ──
    p0 = doc[0]
    # Player name — covers the "______" blank line at y=131
    p0.draw_rect(fitz.Rect(72, 119, 360, 137), color=(1,1,1), fill=(1,1,1))
    p0.insert_text((73, 131), full_name, fontsize=11, color=(0,0,0))
    # Effective date — covers the blank after "effective as of" at y=114
    p0.draw_rect(fitz.Rect(300, 101, 545, 120), color=(1,1,1), fill=(1,1,1))
    p0.insert_text((302, 114), date_top, fontsize=11, color=(0,0,0))

    # ── Page 3 (index 2): CLIENT SIGNATURE, DATE, Print Name ────────────
    p2 = doc[2]
    # Signature image — in the space below "CLIENT SIGNATURE:" (y=217) and above "DATE:" (y=267)
    sig_rect = fitz.Rect(72, 222, 380, 262)
    p2.insert_image(sig_rect, stream=sig_bytes)
    # Date signed — after "DATE:" at y=267
    p2.draw_rect(fitz.Rect(110, 255, 400, 275), color=(1,1,1), fill=(1,1,1))
    p2.insert_text((112, 269), sign_date, fontsize=11, color=(0,0,0))
    # Print name — below date
    p2.insert_text((72, 290), f"Print Name: {print_name}", fontsize=11, color=(0,0,0))

    os.makedirs(SIGNED_DOCS_DIR, exist_ok=True)
    filename = f"signed_{contract.id}_{uuid.uuid4().hex[:10]}.pdf"
    filepath = os.path.join(SIGNED_DOCS_DIR, filename)
    doc.save(filepath)
    doc.close()

    _backup_signed_doc_to_s3(filepath, filename)
    contract.status = "signed"
    contract.signed_pdf_path = filename
    contract.signed_at = datetime.utcnow()
    contract.signer_ip = request.client.host if request.client else None
    db.commit()

    return templates.TemplateResponse("sign_done.html", {"request": request, "contract": contract})

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    # Verify the session cookie belongs to this user_id
    session_cookie = websocket.cookies.get("session")
    if not session_cookie:
        await websocket.close(code=4001)
        return
    # Decode and verify session matches requested user_id
    try:
        import itsdangerous as _itsd
        import json as _json
        from base64 import b64decode as _b64d
        _signer = _itsd.TimestampSigner(str(_session_secret))
        _data = _signer.unsign(session_cookie, max_age=SESSION_MAX_AGE)
        _session_data = _json.loads(_b64d(_data))
        if _session_data.get("user_id") != user_id:
            await websocket.close(code=4003)
            return
    except Exception:
        await websocket.close(code=4001)
        return

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        await websocket.close(code=4001)
        return

    await manager.connect(user_id, websocket)
    try:
        _ws_msg_count = 0
        _ws_window_start = datetime.utcnow()
        while True:
            await websocket.receive_text()
            _ws_msg_count += 1
            _elapsed = (datetime.utcnow() - _ws_window_start).total_seconds()
            if _elapsed < 1.0 and _ws_msg_count > 20:
                await websocket.close(code=4029)
                break
            if _elapsed >= 1.0:
                _ws_msg_count = 0
                _ws_window_start = datetime.utcnow()
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)


def _backup_signed_doc_to_s3(filepath: str, filename: str):
    """Upload signed legal doc to S3 as backup."""
    try:
        s3.upload_fileobj(
            open(filepath, "rb"),
            SPACES_BUCKET,
            f"signed-docs-backup/{filename}",
            ExtraArgs={"ContentType": "application/pdf"}
        )
    except Exception:
        pass

UPLOAD_DIR = "/home/recruiting/bearcats/static/uploads"
SIGNED_DOCS_DIR = "/home/recruiting/bearcats/signed_docs"
TEMPLATE_PDF = "/home/recruiting/bearcats/static/docs/cap_agreement.pdf"

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}

@app.post("/profile/upload-photo")
async def upload_photo(request: Request, photo: UploadFile = File(...), target_user_id: str = Form(default=""), db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "Not logged in"}, status_code=401)

    ext = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "Invalid file type. Use JPG, PNG, GIF, or WebP."}, status_code=400)

    contents = await photo.read()
    if len(contents) > 5 * 1024 * 1024:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "File too large. Max 5MB."}, status_code=400)

    # Validate actual image content via PIL before writing to disk
    try:
        import io as _io
        from PIL import Image as _PIL_Image
        _img = _PIL_Image.open(_io.BytesIO(contents))
        _img.verify()
    except Exception:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "Invalid image file."}, status_code=400)

    # Allow admin to upload photo for another user via target_user_id form field
    logged_in_user = db.query(User).filter(User.id == user_id).first()
    if target_user_id.strip().isdigit() and logged_in_user and logged_in_user.is_admin:
        target_user_id = int(target_user_id.strip())
    else:
        target_user_id = user_id

    # Upload to S3 instead of local disk for security (non-enumerable URLs)
    import io as _io2
    from PIL import Image as _PIL2, ImageOps as _ImageOps2
    img = _PIL2.open(_io2.BytesIO(contents))
    img = _ImageOps2.exif_transpose(img)
    img = img.convert("RGB")
    img.thumbnail((1200, 1200), _PIL2.LANCZOS)
    buf = _io2.BytesIO()
    img.save(buf, format="JPEG", quality=82, optimize=True)
    buf.seek(0)

    s3_key = f"profile-photos/{target_user_id}/{uuid.uuid4().hex}.jpg"
    try:
        s3.upload_fileobj(
            buf, SPACES_BUCKET, s3_key,
            ExtraArgs={"ContentType": "image/jpeg", "ACL": "public-read"}
        )
    except Exception:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "Upload failed. Please try again."}, status_code=500)

    new_photo_url = f"{SPACES_BASE_URL}/{s3_key}"

    target_user = db.query(User).filter(User.id == target_user_id).first()
    if target_user and target_user.role == "player":
        p = db.query(PlayerProfile).filter(PlayerProfile.user_id == target_user_id).first()
        if p is None:
            p = PlayerProfile(user_id=target_user_id)
            db.add(p)
        # Delete old photo from S3 if it was an S3 URL
        if p.photo and SPACES_BASE_URL in p.photo:
            try:
                old_key = p.photo.replace(f"{SPACES_BASE_URL}/", "")
                s3.delete_object(Bucket=SPACES_BUCKET, Key=old_key)
            except Exception:
                pass
        # Delete old local photo if exists
        elif p.photo and os.path.exists(os.path.join(UPLOAD_DIR, os.path.basename(p.photo))):
            try:
                os.remove(os.path.join(UPLOAD_DIR, os.path.basename(p.photo)))
            except Exception:
                pass
        p.photo = new_photo_url
    else:
        c = db.query(CoachProfile).filter(CoachProfile.user_id == target_user_id).first()
        if c is None:
            c = CoachProfile(user_id=target_user_id)
            db.add(c)
        if c.photo and SPACES_BASE_URL in c.photo:
            try:
                old_key = c.photo.replace(f"{SPACES_BASE_URL}/", "")
                s3.delete_object(Bucket=SPACES_BUCKET, Key=old_key)
            except Exception:
                pass
        elif c.photo and os.path.exists(os.path.join(UPLOAD_DIR, os.path.basename(c.photo))):
            try:
                os.remove(os.path.join(UPLOAD_DIR, os.path.basename(c.photo)))
            except Exception:
                pass
        c.photo = new_photo_url
    db.commit()

    # Redirect admin back to the target user's admin edit page, others to their own edit page
    if logged_in_user and logged_in_user.is_admin and target_user_id != user_id:
        return RedirectResponse(f"/admin/users/{target_user_id}/edit-profile", status_code=302)
    return RedirectResponse("/profile/edit", status_code=302)

@app.post("/profile/images/{image_id}/pin")
async def pin_profile_image(image_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    form = await request.form()
    redirect_to = _safe_redirect(form.get("redirect_to", "/profile/edit"), "/profile/edit")
    logged_in = db.query(User).filter(User.id == user_id).first()
    img = db.query(ProfileImage).filter(ProfileImage.id == image_id).first()
    if not img:
        return RedirectResponse(redirect_to, status_code=302)
    # Only owner or admin can pin
    if img.user_id != user_id and not (logged_in and logged_in.is_admin):
        return RedirectResponse(redirect_to, status_code=302)
    if img.is_pinned:
        img.is_pinned = False
    else:
        pinned_count = db.query(ProfileImage).filter(
            ProfileImage.user_id == img.user_id,
            ProfileImage.is_pinned == True
        ).count()
        if pinned_count < 5:
            img.is_pinned = True
    db.commit()
    return RedirectResponse(redirect_to, status_code=302)

@app.post("/messages/{username}")
async def conversation_post(username: str, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    sender = db.query(User).filter(User.id == user_id).first()
    peer = db.query(User).filter(User.username == username).first()
    if not peer:
        raise HTTPException(status_code=404)
    # Players can only message coaches or admins, not other players
    if sender and sender.role == "player" and peer.role == "player":
        raise HTTPException(status_code=403, detail="Players cannot message other players.")
    # Only coaches, admins, or players (replying to coaches) can send messages
    if sender and sender.role not in ("coach", "player") and not sender.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to send messages.")
    form = await request.form()
    text = form.get("content", "").strip()[:2000]
    if text:
        msg = Message(sender_id=user_id, receiver_id=peer.id, content=encrypt_message(text))
        db.add(msg)
        db.commit()
        db.refresh(msg)

        payload = {
            "type": "message",
            "id": msg.id,
            "sender_id": user_id,
            "sender_username": sender.username,
            "receiver_id": peer.id,
            "content": text,
            "timestamp": msg.timestamp.strftime("%b %d, %I:%M %p"),
        }
        # Push to recipient if online
        await manager.send_to_user(peer.id, payload)
        # Also push back to sender for confirmation
        await manager.send_to_user(user_id, {**payload, "own": True})

        # Push unread badge update to recipient
        unread = unread_sender_count(db, peer.id)
        await manager.send_to_user(peer.id, {"type": "unread", "count": unread})

    return RedirectResponse(f"/messages/{username}", status_code=302)


@app.post("/messages/{username}/send")
async def conversation_send_ajax(username: str, request: Request, db: Session = Depends(get_db)):
    """JSON endpoint for WebSocket-enhanced send (AJAX fallback)."""
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "Not logged in"}, status_code=401)
    sender = db.query(User).filter(User.id == user_id).first()
    peer = db.query(User).filter(User.username == username).first()
    if not peer:
        return JSONResponse({"error": "User not found"}, status_code=404)
    # Players can only message coaches or admins, not other players
    if sender and sender.role == "player" and peer.role == "player":
        return JSONResponse({"error": "Players cannot message other players."}, status_code=403)
    if sender and sender.role not in ("coach", "player") and not sender.is_admin:
        return JSONResponse({"error": "Not authorized to send messages."}, status_code=403)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)
    text = data.get("content", "").strip()[:2000]
    if not text:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    msg = Message(sender_id=user_id, receiver_id=peer.id, content=encrypt_message(text))
    db.add(msg)
    db.commit()
    db.refresh(msg)

    payload = {
        "type": "message",
        "id": msg.id,
        "sender_id": user_id,
        "sender_username": sender.username,
        "receiver_id": peer.id,
        "content": text,
        "timestamp": msg.timestamp.strftime("%b %d, %I:%M %p"),
    }
    await manager.send_to_user(peer.id, payload)
    await manager.send_to_user(user_id, {**payload, "own": True})

    unread = unread_sender_count(db, peer.id)
    await manager.send_to_user(peer.id, {"type": "unread", "count": unread})

    return JSONResponse({"ok": True, "message": payload})



@app.post("/admin/migrate-local-photos")
async def admin_migrate_local_photos(request: Request, db: Session = Depends(get_db)):
    """One-time migration: move local /static/uploads/ photos to S3."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    import io as _mig_io
    migrated = 0
    for profile in db.query(PlayerProfile).all():
        if profile.photo and profile.photo.startswith("/static/uploads/"):
            local_path = "/home/recruiting/bearcats" + profile.photo
            if os.path.exists(local_path):
                s3_key = f"profile-photos/{profile.user_id}/{uuid.uuid4().hex}.jpg"
                try:
                    with open(local_path, "rb") as fh:
                        s3.upload_fileobj(fh, SPACES_BUCKET, s3_key, ExtraArgs={"ContentType": "image/jpeg"})
                    profile.photo = f"{SPACES_BASE_URL}/{s3_key}"
                    migrated += 1
                except Exception:
                    pass
    for profile in db.query(CoachProfile).all():
        if profile.photo and profile.photo.startswith("/static/uploads/"):
            local_path = "/home/recruiting/bearcats" + profile.photo
            if os.path.exists(local_path):
                s3_key = f"profile-photos/{profile.user_id}/{uuid.uuid4().hex}.jpg"
                try:
                    with open(local_path, "rb") as fh:
                        s3.upload_fileobj(fh, SPACES_BUCKET, s3_key, ExtraArgs={"ContentType": "image/jpeg"})
                    profile.photo = f"{SPACES_BASE_URL}/{s3_key}"
                    migrated += 1
                except Exception:
                    pass
    db.commit()
    _ip = request.headers.get("x-real-ip", request.client.host if request.client else "")
    log_admin_action(db, admin.id, "migrate_local_photos", detail=f"migrated={migrated}", ip=_ip)
    return JSONResponse({"migrated": migrated})



@app.post("/admin/fix-s3-acl")
async def admin_fix_s3_acl(request: Request, db: Session = Depends(get_db)):
    """Strip public-read ACL from all existing S3 objects, making them private."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    fixed = 0
    errors = 0
    # Collect all S3 keys from DB
    keys = []
    for vid in db.query(Video).all():
        if vid.url and SPACES_BASE_URL in vid.url:
            keys.append(vid.url.replace(f"{SPACES_BASE_URL}/", ""))
    for vid in db.query(Video).all():
        if vid.embed_url and SPACES_BASE_URL in vid.embed_url and vid.embed_url != vid.url:
            keys.append(vid.embed_url.replace(f"{SPACES_BASE_URL}/", ""))
    for img in db.query(ProfileImage).all():
        if img.file_url and SPACES_BASE_URL in img.file_url:
            keys.append(img.file_url.replace(f"{SPACES_BASE_URL}/", ""))
    for tr in db.query(Transcript).all():
        if tr.file_url and SPACES_BASE_URL in tr.file_url:
            keys.append(tr.file_url.replace(f"{SPACES_BASE_URL}/", ""))
    # Also profile photos on S3
    for p in db.query(PlayerProfile).all():
        if p.photo and SPACES_BASE_URL in p.photo:
            keys.append(p.photo.replace(f"{SPACES_BASE_URL}/", ""))
    for c in db.query(CoachProfile).all():
        if c.photo and SPACES_BASE_URL in c.photo:
            keys.append(c.photo.replace(f"{SPACES_BASE_URL}/", ""))
    for key in keys:
        try:
            s3.put_object_acl(Bucket=SPACES_BUCKET, Key=key, ACL="private")
            fixed += 1
        except Exception:
            errors += 1
    _ip = request.headers.get("x-real-ip", request.client.host if request.client else "")
    log_admin_action(db, admin.id, "fix_s3_acl", detail=f"fixed={fixed} errors={errors}", ip=_ip)
    return JSONResponse({"fixed": fixed, "errors": errors})



@app.post("/account/delete")
async def delete_own_account(request: Request, db: Session = Depends(get_db)):
    """Allow users to delete their own account and all associated data."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse("/login", status_code=302)
    form = await request.form()
    confirm = form.get("confirm_delete", "")
    if confirm != "DELETE":
        return RedirectResponse("/profile/edit?delete_error=1", status_code=302)
    # Clean up S3 files
    for vid in db.query(Video).filter(Video.user_id == user_id).all():
        try:
            key = vid.url.replace(f"{SPACES_BASE_URL}/", "")
            s3.delete_object(Bucket=SPACES_BUCKET, Key=key)
        except Exception:
            pass
    for img in db.query(ProfileImage).filter(ProfileImage.user_id == user_id).all():
        try:
            key = img.file_url.replace(f"{SPACES_BASE_URL}/", "")
            s3.delete_object(Bucket=SPACES_BUCKET, Key=key)
        except Exception:
            pass
    for tr in db.query(Transcript).filter(Transcript.user_id == user_id).all():
        try:
            key = tr.file_url.replace(f"{SPACES_BASE_URL}/", "")
            s3.delete_object(Bucket=SPACES_BUCKET, Key=key)
        except Exception:
            pass
    # Delete local profile photo if exists
    pp = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
    cp = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
    for prof in (pp, cp):
        if prof and hasattr(prof, "photo") and prof.photo:
            if SPACES_BASE_URL in prof.photo:
                try:
                    old_key = prof.photo.replace(f"{SPACES_BASE_URL}/", "")
                    s3.delete_object(Bucket=SPACES_BUCKET, Key=old_key)
                except Exception:
                    pass
            else:
                local_path = os.path.join("/home/recruiting/bearcats/static/uploads", os.path.basename(prof.photo))
                if os.path.exists(local_path):
                    try:
                        os.remove(local_path)
                    except Exception:
                        pass
    # Delete DB records
    db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).delete()
    db.query(CoachProfile).filter(CoachProfile.user_id == user_id).delete()
    db.query(Message).filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).delete()
    db.query(Video).filter(Video.user_id == user_id).delete()
    db.query(ProfileImage).filter(ProfileImage.user_id == user_id).delete()
    db.query(Transcript).filter(Transcript.user_id == user_id).delete()
    db.query(Evaluation).filter((Evaluation.coach_id == user_id) | (Evaluation.player_id == user_id)).delete()
    db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user_id).delete()
    db.query(LoginAttempt).filter(LoginAttempt.username == user.username).delete()
    db.delete(user)
    db.commit()
    request.session.clear()
    return RedirectResponse("/?deleted=1", status_code=302)



@app.post("/admin/cleanup-old-ips")
async def admin_cleanup_old_ips(request: Request, db: Session = Depends(get_db)):
    """Anonymize IP addresses in audit logs and login attempts older than 90 days."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
    cutoff = datetime.utcnow() - timedelta(days=90)
    # Anonymize old login attempts
    old_logins = db.query(LoginAttempt).filter(LoginAttempt.attempted_at < cutoff).count()
    db.query(LoginAttempt).filter(LoginAttempt.attempted_at < cutoff).delete()
    # Anonymize old audit log IPs
    old_audits = db.query(AdminAuditLog).filter(AdminAuditLog.created_at < cutoff).update({"ip_address": ""})
    db.commit()
    return JSONResponse({"deleted_login_attempts": old_logins, "anonymized_audit_ips": old_audits})



@app.exception_handler(404)
async def custom_404(request: Request, exc):
    return HTMLResponse(
        content="<html><head><title>Not Found</title></head><body style='font-family:sans-serif;text-align:center;padding:60px;'><h1>404</h1><p>Page not found.</p><a href='/'>Go Home</a></body></html>",
        status_code=404
    )

@app.exception_handler(500)
async def custom_500(request: Request, exc):
    return HTMLResponse(
        content="<html><head><title>Error</title></head><body style='font-family:sans-serif;text-align:center;padding:60px;'><h1>500</h1><p>Something went wrong.</p><a href='/'>Go Home</a></body></html>",
        status_code=500
    )

# ── Stripe Routes ──────────────────────────────────────────────────────────────


@app.get("/join/{token}", response_class=HTMLResponse)
async def join_bypass_get(token: str, request: Request, db: Session = Depends(get_db)):
    rec = db.query(InPersonPaymentToken).filter(InPersonPaymentToken.token == token).first()
    error = None
    if not rec:
        error = "invalid"
    if rec and rec.used_at:
        error = "used"
    if rec and not rec.used_at and rec.expires_at < datetime.utcnow():
        error = "expired"

    if error:
        return templates.TemplateResponse("join.html", {"request": request, "error": error, "token": token})


    # Open token (no user_id set) — for new signups, show landing page
    if rec.user_id is None:
        return templates.TemplateResponse("join.html", {
            "request": request, "error": None, "token": token,
            "open_token": True, "user": None, "already_activated": False,
        })
    user_id = request.session.get("user_id")
    if not user_id:
        request.session["post_login_redirect"] = f"/join/{token}"
        return RedirectResponse("/login", status_code=302)

    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.id != rec.user_id:
        return templates.TemplateResponse("join.html", {"request": request, "error": "wrong_user", "token": token})

    return templates.TemplateResponse("join.html", {
        "request": request, "error": None, "token": token,
        "user": user, "already_activated": user.in_person_paid_until is not None,
    })

@app.post("/join/{token}")
async def join_bypass_post(token: str, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    rec = db.query(InPersonPaymentToken).filter(InPersonPaymentToken.token == token).first()
    if not rec or rec.used_at or rec.expires_at < datetime.utcnow():
        return RedirectResponse(f"/join/{token}", status_code=302)
    if rec.user_id != user_id:
        raise HTTPException(status_code=403, detail="This link is for a different account.")
    user = db.query(User).filter(User.id == user_id).first()
    user.subscription_tier = "premium"
    user.in_person_paid_until = datetime(2027, 3, 26)
    rec.used_at = datetime.utcnow()
    db.commit()
    return RedirectResponse("/dashboard?activated=1", status_code=302)

@app.get("/upgrade", response_class=HTMLResponse)
async def upgrade_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role != "player":
        return RedirectResponse("/dashboard", status_code=302)
    unread_count = unread_sender_count(db, user_id)
    current_tier = user.subscription_tier or "free"
    return templates.TemplateResponse("upgrade.html", {
        "request": request,
        "user": user,
        "unread_count": unread_count,
        "current_tier": current_tier,
        "stripe_key": STRIPE_PUBLISHABLE_KEY,
    })

@app.post("/upgrade/checkout")
async def create_checkout(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role != "player":
        return RedirectResponse("/dashboard", status_code=302)

    form = await request.form()
    tier = form.get("tier", "")
    billing = form.get("billing", "monthly")
    price_map = STRIPE_PRICES_YEARLY if billing == "yearly" else STRIPE_PRICES
    if tier not in price_map or not price_map[tier]:
        return RedirectResponse("/upgrade", status_code=302)

    site_url = os.environ.get("SITE_URL", "https://caprecruiting.com")

    # Get or create Stripe customer
    if user.stripe_customer_id:
        customer_id = user.stripe_customer_id
    else:
        customer = stripe.Customer.create(
            email=user.email,
            name=user.username,
            metadata={"user_id": str(user.id)}
        )
        customer_id = customer.id
        user.stripe_customer_id = customer_id
        db.commit()

    # If user has an existing subscription, redirect to portal instead
    if user.stripe_subscription_id:
        portal = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=f"{site_url}/dashboard",
        )
        return RedirectResponse(portal.url, status_code=302)

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_map[tier], "quantity": 1}],
        mode="subscription",
        success_url=f"{site_url}/upgrade/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{site_url}/upgrade",
        metadata={"user_id": str(user.id), "tier": tier},
        subscription_data={"metadata": {"user_id": str(user.id), "tier": tier}},
    )
    return RedirectResponse(session.url, status_code=302)

@app.get("/upgrade/success", response_class=HTMLResponse)
async def upgrade_success(request: Request, session_id: str = "", db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    unread_count = unread_sender_count(db, user_id)
    request.session["subscription_tier"] = user.subscription_tier or "free"
    return templates.TemplateResponse("upgrade_success.html", {
        "request": request,
        "user": user,
        "unread_count": unread_count,
        "tier": user.subscription_tier or "free",
    })

@app.post("/upgrade/manage")
async def manage_subscription(request: Request, db: Session = Depends(get_db)):
    """Redirect coach to Stripe Customer Portal to cancel/change plan."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role != "player" or not user.stripe_customer_id:
        return RedirectResponse("/upgrade", status_code=302)
    site_url = os.environ.get("SITE_URL", "https://caprecruiting.com")
    portal = stripe.billing_portal.Session.create(
        customer=user.stripe_customer_id,
        return_url=f"{site_url}/dashboard",
    )
    return RedirectResponse(portal.url, status_code=302)

@app.post("/stripe/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook secret not configured")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid webhook")

    def get_user_from_meta(meta):
        uid = meta.get("user_id")
        return db.query(User).filter(User.id == int(uid)).first() if uid else None

    def set_tier(user, tier, sub_id=""):
        if user:
            user.subscription_tier = tier
            if sub_id:
                user.stripe_subscription_id = sub_id
            db.commit()

    # Reject replayed events older than 5 minutes
    import time as _time
    _event_created = event.get("created", 0)
    if _event_created and abs(_time.time() - _event_created) > 300:
        raise HTTPException(status_code=400, detail="Stale webhook event")

    etype = event["type"]

    if etype in ("checkout.session.completed",):
        obj = event["data"]["object"]
        meta = obj.get("metadata", {})
        user = get_user_from_meta(meta)
        tier = meta.get("tier", "free")
        sub_id = obj.get("subscription", "")
        set_tier(user, tier, sub_id)

    elif etype in ("customer.subscription.updated",):
        obj = event["data"]["object"]
        meta = obj.get("metadata", {})
        user = get_user_from_meta(meta)
        status = obj.get("status", "")
        if status == "active":
            tier = meta.get("tier", "free")
            set_tier(user, tier, obj["id"])
        elif status in ("canceled", "unpaid", "past_due"):
            set_tier(user, "free", "")

    elif etype in ("customer.subscription.deleted",):
        obj = event["data"]["object"]
        meta = obj.get("metadata", {})
        user = get_user_from_meta(meta)
        if user:
            user.subscription_tier = "free"
            user.stripe_subscription_id = ""
            db.commit()

    elif etype == "invoice.payment_failed":
        obj = event["data"]["object"]
        cust_id = obj.get("customer", "")
        user = db.query(User).filter(User.stripe_customer_id == cust_id).first()
        if user:
            user.subscription_tier = "free"
            user.stripe_subscription_id = ""
            db.commit()

    return JSONResponse({"ok": True})

# ── School lookup endpoints ────────────────────────────────────────────────────


# ── Questionnaires (Premium Only) ─────────────────────────────────────────────

@app.get("/questionnaires", response_class=HTMLResponse)
async def questionnaires_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role != "player":
        return RedirectResponse("/dashboard", status_code=302)
    if not tier_gte(user.subscription_tier or "free", "premium"):
        return RedirectResponse("/upgrade", status_code=302)
    request.session["subscription_tier"] = user.subscription_tier or "free"
    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("questionnaires.html", {
        "request": request,
        "unread_count": unread_count,
        "data": QUESTIONNAIRE_DATA,
    })

@app.get("/api/schools/states")
def schools_states(request: Request, db: Session = Depends(get_db)):
    from sqlalchemy import text as _text; rows = db.execute(_text("SELECT DISTINCT state FROM schools ORDER BY state")).fetchall()
    return JSONResponse([r[0] for r in rows])

@app.get("/api/schools/cities")
def schools_cities(state: str, request: Request, db: Session = Depends(get_db)):
    from sqlalchemy import text
    rows = db.execute(text("SELECT DISTINCT city FROM schools WHERE state=:state ORDER BY city"), {"state": state.upper()}).fetchall()
    return JSONResponse([r[0] for r in rows])

@app.get("/api/schools/list")
def schools_list(state: str, city: str, request: Request, db: Session = Depends(get_db)):
    from sqlalchemy import text
    rows = db.execute(text("SELECT DISTINCT name FROM schools WHERE state=:state AND city=:city ORDER BY name"), {"state": state.upper(), "city": city}).fetchall()
    return JSONResponse([r[0] for r in rows])
