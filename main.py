import sqlite3
import csv
import io
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
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
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

CSRF_EXEMPT_PATHS = {"/stripe/webhook"}

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
    county = Column(String, default="")
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
    biggest_factors = Column(Text, default="")
    mother_first_name = Column(String, default="")
    mother_last_name = Column(String, default="")
    mother_email = Column(String, default="")
    mother_phone = Column(String, default="")
    father_first_name = Column(String, default="")
    father_last_name = Column(String, default="")
    father_email = Column(String, default="")
    father_phone = Column(String, default="")
    home_address_street = Column(String, default="")
    home_address_city = Column(String, default="")
    home_address_state = Column(String, default="")
    home_address_zip = Column(String, default="")
    news_link1 = Column(String, default="")
    news_link2 = Column(String, default="")
    news_link3 = Column(String, default="")
    news_link4 = Column(String, default="")
    news_link5 = Column(String, default="")

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
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    used_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    note = Column(String, default="")
    source = Column(String, default="admin", index=True)  # "admin" or "self_request"
    requested_email = Column(String, default="", index=True)
    requested_school = Column(String, default="")
    requested_division = Column(String, default="")
    requested_conference = Column(String, default="")

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



class PlayerQuestionnaire(Base):
    __tablename__ = "player_questionnaires"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Personal
    preferred_name = Column(String, default="")
    middle_name = Column(String, default="")
    date_of_birth = Column(String, default="")
    address_street = Column(String, default="")
    address_city = Column(String, default="")
    address_state = Column(String, default="")
    address_zip = Column(String, default="")
    home_phone = Column(String, default="")
    cell_phone = Column(String, default="")
    email = Column(String, default="")
    twitter = Column(String, default="")
    instagram = Column(String, default="")
    hudl_link = Column(String, default="")
    facebook = Column(String, default="")
    best_time_to_call = Column(String, default="")
    # Academic
    school_name = Column(String, default="")
    school_city = Column(String, default="")
    school_state = Column(String, default="")
    school_zip = Column(String, default="")
    school_phone = Column(String, default="")
    counselor_name = Column(String, default="")
    counselor_email = Column(String, default="")
    counselor_phone = Column(String, default="")
    grad_year = Column(String, default="")
    gpa = Column(String, default="")
    sat_composite = Column(String, default="")
    sat_math = Column(String, default="")
    sat_reading = Column(String, default="")
    act_composite = Column(String, default="")
    intended_major = Column(String, default="")
    ncaa_eligibility = Column(String, default="")  # Y/N
    ncaa_eligibility_id = Column(String, default="")
    # Athletic
    height = Column(String, default="")
    weight = Column(String, default="")
    position_offense = Column(String, default="")
    position_defense = Column(String, default="")
    position_special_teams = Column(String, default="")
    jersey_number = Column(String, default="")
    forty_yard = Column(String, default="")
    shuttle = Column(String, default="")
    vertical = Column(String, default="")
    bench_press = Column(String, default="")
    squat = Column(String, default="")
    powerclean = Column(String, default="")
    broad_jump = Column(String, default="")
    wingspan = Column(String, default="")
    other_sports = Column(String, default="")
    athletic_achievements = Column(Text, default="")
    injuries = Column(Text, default="")
    # Parent/Guardian 1
    parent1_first_name = Column(String, default="")
    parent1_last_name = Column(String, default="")
    parent1_relationship = Column(String, default="")
    parent1_email = Column(String, default="")
    parent1_cell_phone = Column(String, default="")
    parent1_business_phone = Column(String, default="")
    parent1_occupation = Column(String, default="")
    parent1_college = Column(String, default="")
    parent1_address = Column(String, default="")
    # Parent/Guardian 2
    parent2_first_name = Column(String, default="")
    parent2_last_name = Column(String, default="")
    parent2_relationship = Column(String, default="")
    parent2_email = Column(String, default="")
    parent2_cell_phone = Column(String, default="")
    parent2_business_phone = Column(String, default="")
    parent2_occupation = Column(String, default="")
    parent2_college = Column(String, default="")
    parent2_address = Column(String, default="")
    # Family
    siblings = Column(Text, default="")
    # Influential people
    influential_person1 = Column(String, default="")
    influential_person2 = Column(String, default="")
    # Club/Travel Team
    club_team_name = Column(String, default="")
    club_coach_name = Column(String, default="")
    club_coach_email = Column(String, default="")
    club_coach_phone = Column(String, default="")
    # Coaching
    head_coach_name = Column(String, default="")
    head_coach_phone = Column(String, default="")
    head_coach_email = Column(String, default="")
    school_fax = Column(String, default="")
    # Recruitment
    top_schools = Column(Text, default="")
    offers = Column(Text, default="")
    film_link = Column(String, default="")
    connection_to_school = Column(Text, default="")
    campus_visits = Column(Text, default="")
    planned_visits = Column(Text, default="")
    decision_timeline = Column(String, default="")

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=False, index=True)
    username = Column(String, default="")
    attempted_at = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=False)


class ScoutBoardLane(Base):
    __tablename__ = "scout_board_lanes"
    id = Column(Integer, primary_key=True)
    college = Column(String, nullable=False, index=True)  # e.g. "Kent State"
    name = Column(String, nullable=False)
    sort_order = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

class ScoutBoardCard(Base):
    __tablename__ = "scout_board_cards"
    id = Column(Integer, primary_key=True)
    college = Column(String, nullable=False, index=True)
    lane_id = Column(Integer, ForeignKey("scout_board_lanes.id"), nullable=False)
    sort_order = Column(Integer, default=0)
    # Player reference — either linked to a platform user OR custom
    player_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    custom_first_name = Column(String, default="")
    custom_last_name = Column(String, default="")
    custom_high_school = Column(String, default="")
    custom_grad_year = Column(String, default="")
    custom_position = Column(String, default="")
    # Tile fields
    tile_image_url = Column(String, default="")
    visit_date = Column(String, default="")  # scheduled campus visit
    high_school_visit_date = Column(String, default="")  # scheduled HS visit
    scout_name = Column(String, default="")
    notes = Column(Text, default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    archived_at = Column(DateTime, nullable=True, index=True)
    archived_by = Column(Integer, ForeignKey("users.id"), nullable=True)

class ScoutBoardScout(Base):
    __tablename__ = "scout_board_scouts"
    id = Column(Integer, primary_key=True)
    college = Column(String, nullable=False, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class AdminAuditLog(Base):
    __tablename__ = "admin_audit_log"
    id = Column(Integer, primary_key=True)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String, nullable=False)
    target_id = Column(Integer, nullable=True)
    detail = Column(Text, default="")
    ip_address = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class VerifiedStat(Base):
    __tablename__ = "verified_stats"
    id = Column(Integer, primary_key=True)
    player_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    stat_field = Column(String, nullable=False)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    verified_at = Column(DateTime, default=datetime.utcnow)

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    type = Column(String, default="signup", index=True)
    title = Column(String, default="")
    body = Column(String, default="")
    link = Column(String, default="")
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_read = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class MarketingLead(Base):
    __tablename__ = "marketing_leads"
    id = Column(Integer, primary_key=True)
    name = Column(String, default="")
    email = Column(String, default="", index=True)
    phone = Column(String, default="")
    role = Column(String, default="")  # coach / hs_coach / parent / player / partner / other
    school = Column(String, default="")
    state = Column(String, default="")
    division = Column(String, default="")
    conference = Column(String, default="")
    stage = Column(String, default="new", index=True)  # new / contacted / responded / demo / onboarded / inactive
    source = Column(String, default="")  # manual / self_request / coach_account / csv / other
    tags = Column(String, default="")  # comma-separated
    notes = Column(Text, default="")
    last_contacted_at = Column(DateTime, nullable=True)
    next_followup_at = Column(DateTime, nullable=True, index=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MarketingActivity(Base):
    __tablename__ = "marketing_activities"
    id = Column(Integer, primary_key=True)
    lead_id = Column(Integer, ForeignKey("marketing_leads.id"), nullable=False, index=True)
    type = Column(String, default="note")  # email / call / text / meeting / note
    direction = Column(String, default="out")  # out / in
    subject = Column(String, default="")
    body = Column(Text, default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

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



# --- Rate limiting for signup, forgot-password, messaging ---
_rate_limit_store: Dict[str, list] = {}

def _check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """Return True if rate limit exceeded."""
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window_seconds)
    if key not in _rate_limit_store:
        _rate_limit_store[key] = []
    _rate_limit_store[key] = [t for t in _rate_limit_store[key] if t > cutoff]
    if len(_rate_limit_store[key]) >= max_requests:
        return True
    _rate_limit_store[key].append(now)
    return False

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
        "Big 12": {
            "BYU": "https://www.byuathletemanager.com/Questionnaire/Form/1",
            "Utah": "https://questionnaires.armssoftware.com/c15fb5f63631",
            "Houston": "https://uhcougars.com/documents/2019/8/12/gen_Student_Athlete_Bios.pdf",
            "Arizona State": "https://questionnaires.armssoftware.com/ab20d3134f9d",
            "TCU": "https://questionnaires.armssoftware.com/e4a9a3843416",
            "Cincinnati": "https://questionnaires.armssoftware.com/d7c18b19b6cc",
            "Kansas State": "https://questionnaires.armssoftware.com/8fd884a36fbc",
            "Baylor": "https://questionnaires.armssoftware.com/aa72ebcc5cb6",
            "Kansas": "https://college.jumpforward.com/questionnaire.aspx?iid=332&sportid=18",
            "UCF": "https://questionnaires.armssoftware.com/316449b71334",
            "West Virginia": "https://college.jumpforward.com/questionnaire.aspx?iid=1599&sportid=18",
            "Colorado": "https://college.jumpforward.com/questionnaire.aspx?iid=1684&sportid=18",
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
        "AAC": {
            "Navy": "https://questionnaires.armssoftware.com/603ee6dadcf8",
            "Tulane": "https://questionnaires.armssoftware.com/1c01a8dbf7a3",
            "East Carolina": "https://questionnaires.armssoftware.com/54e0439b932b",
            "South Florida": "https://gousfbulls.com/sb_output.aspx?form=3",
            "Memphis": "https://memphis.collegewarroom.com/Questionnaire/Form/1",
            "Army": "https://questionnaires.armssoftware.com/68966b661b5d",
            "UTSA": "https://questionnaires.armssoftware.com/1a6c084f40d1",
            "Temple": "https://owlsports.com/form/15",
            "Florida Atlantic": "https://questionnaires.armssoftware.com/4f0d0d975c59",
            "Tulsa": "https://questionnaires.armssoftware.com/0596f42dbdd9",
            "Charlotte": "https://questionnaires.armssoftware.com/2b0570a8394a",
        },
        "FBS Independent": {
            "Notre Dame": "https://questionnaires.armssoftware.com/f0393f4128e2",
            "UConn": "https://questionnaires.armssoftware.com/a34f74e9b093",
        },
        "Mountain West": {
            "New Mexico": "https://questionnaires.armssoftware.com/fc6335185ee7",
            "San Diego State": "https://questionnaires.armssoftware.com/16c63dea081e",
            "Boise State": "https://questionnaires.armssoftware.com/654c9875b45c",
            "Hawai'i": "https://questionnaires.armssoftware.com/79737af39e0a",
            "Utah State": "https://questionnaires.armssoftware.com/eafac485e970",
            "Air Force": "https://questionnaires.armssoftware.com/eff272a5aeb4",
            "Wyoming": "https://college.jumpforward.com/questionnaire.aspx?iid=556&sportid=54",
            "Nevada": "https://questionnaires.armssoftware.com/6f8b6c2472a1",
            "San Jose State": "https://questionnaires.armssoftware.com/a685a82d7583",
            "Colorado State": "https://questionnaires.armssoftware.com/c965bf3e644e",
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
        "North Coast Athletic": {
            "John Carroll": "https://admission.jcu.edu/register/?id=645ec1ea-84e4-4435-a94a-45fca721e70e",
            "DePauw": "https://questionnaires.armssoftware.com/f97bc5322c35",
            "Wabash": "https://apply.wabash.edu/register/?id=27592af4-acd2-4ebc-bc27-f739c0c72d66&sys:field:athletic_interest=2c825de6-ae6b-446b-8059-d25608073589",
            "Denison": "https://denisonbigred.com/sports/2020/6/15/football_recruit_questionnaire.aspx",
            "Wooster": "https://woosterathletics.com/sports/2025/6/25/football-prospective-scot-recruiting-form.aspx",
            "Wittenberg": "https://wittenbergtigers.com/recruiting/forms/fball",
            "Ohio Wesleyan": "https://battlingbishops.com/sb_output.aspx?frform=5&path=football&",
            "Kenyon": "https://forms.arirecruiting.com/kenyon_football/recruitquestionnaire",
            "Oberlin": "https://questionnaires.armssoftware.com/e69fe473c327",
        },
        "New Jersey Athletic": {
            "Salisbury": "https://questionnaires.armssoftware.com/d89de0126880",
            "Rowan": "https://questionnaires.armssoftware.com/f7989855e660",
            "Montclair State": "https://montclairathletics.com/sb_output.aspx?form=3",
            "TCNJ": "https://tcnjathletics.com/sports/2025/7/1/recruit-landing.aspx",
            "Kean": "https://questionnaires.armssoftware.com/f0f956552475",
            "William Paterson": "https://www.wpupioneers.com/sb_output.aspx?form=20",
            "Castleton": "https://castletonsports.com/sports/2020/8/31/football-recruit.aspx",
        },
    },
}
@app.get("/api/schools/county")
def schools_county(state: str, city: str, school: str, request: Request, db: Session = Depends(get_db)):
    from sqlalchemy import text as _text
    row = db.execute(_text("SELECT county FROM schools WHERE state=:state AND city=:city AND name=:school LIMIT 1"), {"state": state.upper(), "city": city, "school": school}).fetchone()
    return row[0] if row and row[0] else ""

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

PARTNER_SCHOOLS = [
    ('notre_dame', 'Notre Dame', True),
    ('ohio_state', 'Ohio State', True),
    ('clemson', 'Clemson', True),
    ('penn_state', 'Penn State', True),
    ('texas_aandm', 'Texas A&M', True),
    ('ucla', 'UCLA', True),
    ('wisconsin', 'Wisconsin', True),
    ('tcu', 'TCU', True),
    ('mississippi_state', 'Mississippi State', True),
    ('syracuse', 'Syracuse', True),
    ('air_force', 'Air Force', True),
    ('akron', 'Akron', True),
    ('albany', 'Albany', True),
    ('albright', 'Albright', False),
    ('alfred', 'Alfred', False),
    ('alfred_state', 'Alfred State', False),
    ('allegheny', 'Allegheny', False),
    ('alvernia', 'Alvernia', True),
    ('army', 'Army', True),
    ('bloomsburg', 'Bloomsburg', False),
    ('boston_college', 'Boston College', True),
    ('bryant', 'Bryant', True),
    ('bucknell', 'Bucknell', True),
    ('buffalo', 'Buffalo', True),
    ('buffalo_state', 'Buffalo State', False),
    ('catholic', 'Catholic', True),
    ('central_connecticut_state', 'Central Connecticut State', True),
    ('charlotte', 'Charlotte', True),
    ('cincinnati', 'Cincinnati', True),
    ('clarion', 'Clarion', True),
    ('colgate', 'Colgate', True),
    ('colorado', 'Colorado', True),
    ('columbia', 'Columbia', True),
    ('concord', 'Concord', False),
    ('cornell', 'Cornell', True),
    ('dartmouth', 'Dartmouth', True),
    ('delaware', 'Delaware', True),
    ('delaware_state', 'Delaware State', True),
    ('delaware_valley', 'Delaware Valley', False),
    ('duquesne', 'Duquesne', True),
    ('east_carolina', 'East Carolina', True),
    ('east_stroudsburg', 'East Stroudsburg', True),
    ('eastern', 'Eastern', False),
    ('edinboro', 'Edinboro', True),
    ('elon', 'Elon', True),
    ('emporia_state', 'Emporia State', True),
    ('endicott', 'Endicott', True),
    ('fairmont_state', 'Fairmont State', False),
    ('florida_atlantic', 'Florida Atlantic', True),
    ('fordham', 'Fordham', True),
    ('gannon', 'Gannon', False),
    ('gardner_webb', 'Gardner-Webb', True),
    ('geneva', 'Geneva', False),
    ('georgetown', 'Georgetown', True),
    ('gettysburg', 'Gettysburg', False),
    ('harvard', 'Harvard', True),
    ('holy_cross', 'Holy Cross', True),
    ('illinois_wesleyan', 'Illinois Wesleyan', False),
    ('indiana', 'Indiana', True),
    ('indiana_state', 'Indiana State', True),
    ('indiana_university_of_pennsylvania', 'Indiana University of Pennsylvania', True),
    ('ithaca', 'Ithaca', True),
    ('james_madison', 'James Madison', True),
    ('john_carroll', 'John Carroll', True),
    ('johns_hopkins', 'Johns Hopkins', False),
    ('juniata', 'Juniata', False),
    ('kent_state', 'Kent State', False),
    ('kentucky', 'Kentucky', True),
    ('kentucky_wesleyan', 'Kentucky Wesleyan', False),
    ('king_s_college', "King's College", True),
    ('kutztown', 'Kutztown', False),
    ('lackawanna', 'Lackawanna', False),
    ('lafayette', 'Lafayette', True),
    ('lebanon_valley', 'Lebanon Valley', False),
    ('lehigh', 'Lehigh', True),
    ('liberty', 'Liberty', True),
    ('lincoln', 'Lincoln', False),
    ('liu', 'LIU', True),
    ('lock_haven', 'Lock Haven', False),
    ('louisiana', 'Louisiana', True),
    ('lycoming', 'Lycoming', False),
    ('marshall', 'Marshall', True),
    ('maryland', 'Maryland', True),
    ('mcdaniel', 'McDaniel', False),
    ('memphis', 'Memphis', True),
    ('mercyhurst', 'Mercyhurst', True),
    ('merrimack', 'Merrimack', True),
    ('millersville', 'Millersville', False),
    ('misericordia', 'Misericordia', False),
    ('monmouth', 'Monmouth', True),
    ('moravian', 'Moravian', False),
    ('muhlenberg', 'Muhlenberg', True),
    ('new_hampshire', 'New Hampshire', True),
    ('new_haven', 'New Haven', False),
    ('norfolk_state', 'Norfolk State', True),
    ('north_dakota_state', 'North Dakota State', True),
    ('north_greenville', 'North Greenville', True),
    ('north_texas', 'North Texas', True),
    ('ohio', 'Ohio', True),
    ('ohio_dominican', 'Ohio Dominican', True),
    ('pace', 'Pace', True),
    ('penn', 'Penn', True),
    ('pittsburgh', 'Pittsburgh', True),
    ('quincy', 'Quincy', True),
    ('randolph_macon', 'Randolph-Macon', True),
    ('richmond', 'Richmond', True),
    ('rockford', 'Rockford', True),
    ('rutgers', 'Rutgers', True),
    ('saint_anselm', 'Saint Anselm', True),
    ('saint_vincent', 'Saint Vincent', False),
    ('salisbury', 'Salisbury', False),
    ('seton_hill', 'Seton Hill', False),
    ('shenandoah', 'Shenandoah', True),
    ('shepherd', 'Shepherd', True),
    ('shippensburg', 'Shippensburg', False),
    ('slippery_rock', 'Slippery Rock', True),
    ('stevenson', 'Stevenson', False),
    ('stony_brook', 'Stony Brook', True),
    ('sussex', 'Sussex', False),
    ('temple', 'Temple', True),
    ('tennessee_tech', 'Tennessee Tech', False),
    ('thiel', 'Thiel', True),
    ('toledo', 'Toledo', True),
    ('towson', 'Towson', True),
    ('troy', 'Troy', True),
    ('uconn', 'UConn', True),
    ('umass', 'UMass', True),
    ('unc_pembroke', 'UNC Pembroke', False),
    ('ursinus', 'Ursinus', False),
    ('ut_martin', 'UT Martin', True),
    ('vanderbilt', 'Vanderbilt', True),
    ('villanova', 'Villanova', True),
    ('virginia_military_institute', 'Virginia Military Institute', True),
    ('virginia_union', 'Virginia Union', False),
    ('wagner', 'Wagner', True),
    ('wake_forest', 'Wake Forest', True),
    ('washington_and_jefferson', 'Washington & Jefferson', True),
    ('west_chester', 'West Chester', False),
    ('west_liberty', 'West Liberty', True),
    ('west_virginia_wesleyan', 'West Virginia Wesleyan', True),
    ('wheeling', 'Wheeling', False),
    ('widener', 'Widener', False),
    ('wilkes', 'Wilkes', False),
    ('william_and_mary', 'William & Mary', True),
    ('wofford', 'Wofford', True),
    ('youngstown_state', 'Youngstown State', True),
]

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=302)
    return templates.TemplateResponse("home.html", {
        "request": request,
        "partner_schools": PARTNER_SCHOOLS,
    })

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
    school_county: str = Form(""),
    invite_token: Optional[str] = Form(None),
    bypass_token: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "unknown"
    if _check_rate_limit(f"signup:{client_ip}", 5, 3600):
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Too many signup attempts. Please try again later."})
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
        db.add(PlayerProfile(user_id=user.id, team_id=team_id, school=school_name.strip(), city=school_city.strip(), state=school_state.strip(), county=school_county.strip()))
    else:
        db.add(CoachProfile(user_id=user.id, team_id=coach_tid, division=coach_division.strip(), conference=coach_conference.strip(), college=coach_college.strip()))
    db.commit()

    if role == "player":
        try:
            _notify_coaches_of_new_player(db, user, school_name.strip())
        except Exception as _e:
            _logger.warning("Notification fan-out failed: %s", type(_e).__name__)

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

@app.post("/coach-request")
async def coach_request_post(request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if _check_rate_limit(f"coach_req:{client_ip}", 5, 3600):
        return JSONResponse({"error": "Too many requests from this address. Please try again later."}, status_code=429)
    try:
        data = await request.json()
    except Exception:
        data = {}
    email = (data.get("email") or "").strip().lower()[:200]
    school = (data.get("school") or "").strip()[:200]
    division = (data.get("division") or "").strip()[:50]
    conference = (data.get("conference") or "").strip()[:100]
    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return JSONResponse({"error": "Please enter a valid email address."}, status_code=400)
    if not school:
        return JSONResponse({"error": "Please select your college."}, status_code=400)
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return JSONResponse({"error": "An account already exists for this email. Please sign in instead."}, status_code=400)
    # Reuse pending invite if present
    pending = db.query(CoachInvite).filter(
        CoachInvite.requested_email == email,
        CoachInvite.source == "self_request",
        CoachInvite.used == False,
        CoachInvite.expires_at > datetime.utcnow(),
    ).first()
    if pending:
        invite = pending
    else:
        token = uuid.uuid4().hex
        invite = CoachInvite(
            token=token,
            created_by=None,
            expires_at=datetime.utcnow() + timedelta(days=7),
            source="self_request",
            requested_email=email,
            requested_school=school,
            requested_division=division,
            requested_conference=conference,
            note=f"Self-requested by {email}",
        )
        db.add(invite)
        db.commit()
        db.refresh(invite)
    site_url = os.environ.get("SITE_URL", "https://caprecruiting.com")
    signup_link = f"{site_url}/signup?invite={invite.token}"
    import asyncio
    asyncio.create_task(_send_coach_request_emails(email, school, division, conference, signup_link))
    return JSONResponse({"ok": True})

async def _send_coach_request_emails(coach_email: str, school: str, division: str, conference: str, signup_link: str):
    try:
        import aiosmtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from html import escape as _esc
        # Fetch admin emails
        db = SessionLocal()
        try:
            admins = db.query(User).filter(User.is_admin == True).all()
            admin_emails = [a.email for a in admins if a.email]
        finally:
            db.close()
        if not admin_emails:
            admin_emails = [SMTP_USER]
        site_url = os.environ.get("SITE_URL", "https://caprecruiting.com")
        # 1) Email the coach with their signup link
        coach_msg = MIMEMultipart("alternative")
        coach_msg["Subject"] = "Your CAP Recruiting Coach Signup Link"
        coach_msg["From"] = f"CAP Recruiting <{SMTP_USER}>"
        coach_msg["To"] = coach_email
        coach_html = f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px;">
            <h2 style="color:#0a1628;">Welcome to CAP Recruiting</h2>
            <p>Thanks for requesting coach access. Click the button below to finish creating your account. This link is valid for 7 days.</p>
            <p style="margin:28px 0;">
                <a href="{_esc(signup_link)}" style="background:#0a1628;color:#f0b429;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px;">Create Your Coach Account</a>
            </p>
            <p style="color:#888;font-size:13px;">If the button doesn't work, copy and paste this link into your browser:<br>{_esc(signup_link)}</p>
        </div>"""
        coach_msg.attach(MIMEText(coach_html, "html"))
        try:
            await aiosmtplib.send(coach_msg, hostname=SMTP_HOST, port=SMTP_PORT, username=SMTP_USER, password=SMTP_PASSWORD, start_tls=True)
        except Exception as e:
            _logger.warning("Coach invite email send failed: %s", type(e).__name__)
        # 2) Email admins with the request details
        for admin_email in admin_emails:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"Coach Access Request: {coach_email}"
            msg["From"] = f"CAP Recruiting <{SMTP_USER}>"
            msg["To"] = admin_email
            admin_html = f"""
            <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px;">
                <h2 style="color:#0a1628;">New Coach Access Request</h2>
                <table style="width:100%;border-collapse:collapse;margin:16px 0;">
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">Email</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{_esc(coach_email)}</td></tr>
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">School</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{_esc(school) or '—'}</td></tr>
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">Division</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{_esc(division) or '—'}</td></tr>
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">Conference</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{_esc(conference) or '—'}</td></tr>
                </table>
                <p style="color:#6b7280;font-size:13px;">A signup link has been emailed to the coach automatically. You can revoke it from <a href="{site_url}/admin/invites" style="color:#0a1628;font-weight:700;">the admin invites page</a> if this looks suspicious.</p>
            </div>"""
            msg.attach(MIMEText(admin_html, "html"))
            try:
                await aiosmtplib.send(msg, hostname=SMTP_HOST, port=SMTP_PORT, username=SMTP_USER, password=SMTP_PASSWORD, start_tls=True)
            except Exception as e:
                _logger.warning("Coach request admin email failed: %s", type(e).__name__)
    except Exception as e:
        _logger.warning("Coach request email flow error: %s", type(e).__name__)


def _notify_coaches_of_new_player(db: Session, new_user: "User", school: str):
    """Insert one Notification row per coach for the new player signup."""
    coaches = db.query(User).filter(User.role == "coach").all()
    if not coaches:
        return
    display = new_user.username
    body = f"{school}" if school else ""
    link = f"/profile/{new_user.username}"
    for c in coaches:
        db.add(Notification(
            user_id=c.id,
            type="signup",
            title=f"New player: {display}",
            body=body,
            link=link,
            actor_user_id=new_user.id,
        ))
    db.commit()

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
            from html import escape as _esc
            _safe_user = _esc(player_username)
            _safe_email = _esc(player_email)
            _safe_school = _esc(school) if school else "—"
            html = f"""
            <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;">
                <h2 style="color:#0a1628;">New Player Signed Up</h2>
                <table style="width:100%;border-collapse:collapse;margin:16px 0;">
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">Username</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{_safe_user}</td></tr>
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">Email</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{_safe_email}</td></tr>
                    <tr><td style="padding:8px 0;color:#6b7280;font-size:14px;">School</td><td style="padding:8px 0;font-weight:700;color:#0a1628;">{_safe_school}</td></tr>
                </table>
                <a href="{site_url}/profile/{_safe_user}" style="background:#0a1628;color:#f0b429;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;font-size:14px;">View Profile</a>
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
    client_ip = request.client.host if request.client else "unknown"
    if _check_rate_limit(f"forgot:{client_ip}", 3, 3600):
        return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": True, "error": None})
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
    user.session_version = (user.session_version or 0) + 1
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
    request.session["session_version"] = user.session_version or 0
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

# GET /logout redirects to homepage (use POST to actually log out)
@app.get("/logout")
async def logout_get(request: Request):
    return RedirectResponse("/", status_code=302)

# ── Google OAuth 2.0 ──────────────────────────────────────────────────────────
import urllib.parse as _urlparse
import secrets as _secrets
import httpx

@app.get("/auth/google")
async def google_auth_redirect(request: Request, invite: str = "", db: Session = Depends(get_db)):
    """Redirect user to Google's consent screen."""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")
    state = _secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    # Preserve coach invite token through the OAuth flow
    if invite:
        inv = db.query(CoachInvite).filter(CoachInvite.token == invite, CoachInvite.used == False).first()
        if inv and inv.expires_at > datetime.utcnow():
            request.session["oauth_invite"] = invite
    params = _urlparse.urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": f"{SITE_URL}/auth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    })
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")

@app.get("/auth/google/callback")
async def google_auth_callback(request: Request, code: str = "", state: str = "", error: str = "", db: Session = Depends(get_db)):
    """Handle Google's redirect back with auth code."""
    if error:
        return RedirectResponse("/login?error=google_denied", status_code=302)
    saved_state = request.session.pop("oauth_state", "")
    if not state or state != saved_state:
        _logger.error(f"Google OAuth state mismatch: got={state!r} saved={saved_state!r} session_keys={list(request.session.keys())}")
        return RedirectResponse("/login?error=google_state", status_code=302)
    # Exchange code for tokens
    try:
        async with httpx.AsyncClient() as client:
            token_resp = await client.post("https://oauth2.googleapis.com/token", data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": f"{SITE_URL}/auth/google/callback",
                "grant_type": "authorization_code",
            })
            if token_resp.status_code != 200:
                _logger.error(f"Google token exchange failed: {token_resp.status_code} {token_resp.text[:500]}")
                return RedirectResponse("/login?error=google_token", status_code=302)
            tokens = token_resp.json()
            # Get user info
            userinfo_resp = await client.get("https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {tokens['access_token']}"})
            if userinfo_resp.status_code != 200:
                _logger.error(f"Google userinfo failed: {userinfo_resp.status_code}")
                return RedirectResponse("/login?error=google_userinfo", status_code=302)
            guser = userinfo_resp.json()
    except Exception as exc:
        _logger.error(f"Google OAuth exception: {exc}")
        return RedirectResponse("/login?error=google_exception", status_code=302)

    google_email = guser.get("email", "").strip().lower()
    if not google_email:
        return RedirectResponse("/login?error=google_failed", status_code=302)

    # Check if user already exists with this email
    user = db.query(User).filter(User.email == google_email).first()
    if user:
        # Existing user — log them in
        request.session.clear()
        request.session["user_id"] = user.id
        request.session["is_admin"] = bool(user.is_admin)
        request.session["role"] = user.role
        request.session["subscription_tier"] = user.subscription_tier or "free"
        request.session["session_version"] = user.session_version or 0
        return RedirectResponse("/dashboard", status_code=302)

    # New user — check for coach invite token
    invite_token = request.session.pop("oauth_invite", "")
    is_coach = False
    if invite_token:
        inv = db.query(CoachInvite).filter(CoachInvite.token == invite_token, CoachInvite.used == False).first()
        if inv and inv.expires_at > datetime.utcnow():
            is_coach = True

    google_name = guser.get("name", "")
    first_name = guser.get("given_name", "")
    last_name = guser.get("family_name", "")
    # Generate unique username from email prefix
    base_username = google_email.split("@")[0]
    base_username = re.sub(r'[^a-zA-Z0-9_]', '', base_username)[:20]
    username = base_username
    suffix = 1
    while db.query(User).filter(User.username == username).first():
        username = f"{base_username}{suffix}"
        suffix += 1

    # Create user with a random password (they'll use Google to log in)
    random_pw = _secrets.token_urlsafe(32)
    role = "coach" if is_coach else "player"
    new_user = User(
        username=username,
        email=google_email,
        password_hash=hash_password(random_pw),
        role=role,
        subscription_tier="free",
        public_id=uuid.uuid4().hex[:12],
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Create profile based on role — must succeed or we roll back the user
    try:
        if is_coach:
            db.add(CoachProfile(user_id=new_user.id, first_name=first_name, last_name=last_name))
            inv.used = True
            inv.used_by = new_user.id
        else:
            db.add(PlayerProfile(user_id=new_user.id, first_name=first_name, last_name=last_name))
        db.commit()
    except Exception as _profile_exc:
        _logger.error("OAuth profile creation failed for user %s: %s", new_user.id, type(_profile_exc).__name__)
        db.rollback()
        # Retry with a bare-minimum profile so the user is never left orphaned
        try:
            if is_coach:
                db.add(CoachProfile(user_id=new_user.id))
            else:
                db.add(PlayerProfile(user_id=new_user.id))
            db.commit()
        except Exception:
            db.rollback()
            _logger.error("OAuth profile retry also failed for user %s", new_user.id)
            return RedirectResponse("/login?error=google_failed", status_code=302)

    # Log them in
    request.session.clear()
    request.session["user_id"] = new_user.id
    request.session["is_admin"] = False
    request.session["role"] = role
    request.session["subscription_tier"] = "free"
    request.session["session_version"] = 0

    # Send admin notification
    try:
        await send_player_signup_notification(username, google_email, "")
    except Exception:
        pass

    return RedirectResponse("/profile/edit", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, school: Optional[str] = None, year: Optional[str] = None, position: Optional[str] = None, state: Optional[str] = None, city: Optional[str] = None, q: Optional[str] = None, db: Session = Depends(get_db)):
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
    if state:
        query = query.filter(PlayerProfile.state == state)
    if city:
        query = query.filter(PlayerProfile.city == city)
    if school:
        query = query.filter(PlayerProfile.school == school)
    if position:
        query = query.filter(PlayerProfile.position == position)
    q_clean = (q or "").strip()
    if q_clean:
        like = f"%{q_clean}%"
        query = query.filter(
            (PlayerProfile.first_name.ilike(like))
            | (PlayerProfile.last_name.ilike(like))
            | (User.username.ilike(like))
        )
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
        "active_state": state,
        "active_city": city,
        "active_q": q_clean,
    })

@app.get("/profile/me")
async def profile_me(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse("/login", status_code=302)
    return RedirectResponse(f"/profile/{user.username}", status_code=302)

@app.get("/profile/edit", response_class=HTMLResponse)
async def edit_profile_get(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if user.role == "player":
        profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
        if not profile:
            profile = PlayerProfile(user_id=user_id)
            db.add(profile)
            db.commit()
            db.refresh(profile)
    else:
        profile = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
        if not profile:
            profile = CoachProfile(user_id=user_id)
            db.add(profile)
            db.commit()
            db.refresh(profile)
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
        if not p:
            p = PlayerProfile(user_id=user_id)
            db.add(p)
            db.flush()
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
        p.county = form.get("school_county", "")[:100]
        p.mother_first_name = form.get("mother_first_name", "")[:100]
        p.mother_last_name = form.get("mother_last_name", "")[:100]
        p.mother_email = form.get("mother_email", "")[:200]
        p.mother_phone = form.get("mother_phone", "")[:50]
        p.father_first_name = form.get("father_first_name", "")[:100]
        p.father_last_name = form.get("father_last_name", "")[:100]
        p.father_email = form.get("father_email", "")[:200]
        p.father_phone = form.get("father_phone", "")[:50]
        p.home_address_street = form.get("home_address_street", "")[:200]
        p.home_address_city = form.get("home_address_city", "")[:100]
        p.home_address_state = form.get("home_address_state", "")[:10]
        p.home_address_zip = form.get("home_address_zip", "")[:20]
        for _ni in range(1, 6):
            setattr(p, f"news_link{_ni}", form.get(f"news_link{_ni}", "")[:500])
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
        _allowed_factors = {"location", "winning_tradition", "education", "player_development", "opportunity_to_play", "cost", "school_size", "job_placement", "facilities"}
        _selected = [v for v in form.getlist("biggest_factors") if v in _allowed_factors]
        p.biggest_factors = ",".join(_selected)
        # Sync profile changes to questionnaire if it exists
        q = db.query(PlayerQuestionnaire).filter(PlayerQuestionnaire.user_id == user_id).first()
        if q:
            q.email = user.email or ""
            q.cell_phone = p.phone or ""
            q.address_street = p.home_address_street or ""
            q.address_city = p.home_address_city or ""
            q.address_state = p.home_address_state or ""
            q.address_zip = p.home_address_zip or ""
            q.school_name = p.school or ""
            q.school_city = p.city or ""
            q.school_state = p.state or ""
            q.gpa = p.gpa or ""
            q.intended_major = p.intended_major or ""
            q.height = p.height or ""
            q.weight = p.weight or ""
            q.position_offense = p.position or ""
            q.forty_yard = p.forty_yard or ""
            q.bench_press = p.bench_press or ""
            q.squat = p.squat or ""
            q.powerclean = p.clean or ""
            q.vertical = p.vertical or ""
            q.broad_jump = p.broad_jump or ""
            q.wingspan = p.wingspan or ""
            q.shuttle = p.pro_agility or ""
            q.hudl_link = p.hudl_url or ""
            q.film_link = p.hudl_url or ""
            q.twitter = p.x_url or ""
            q.instagram = p.instagram_url or ""
            q.grad_year = p.year or ""
            q.parent1_first_name = p.mother_first_name or ""
            q.parent1_last_name = p.mother_last_name or ""
            q.parent1_email = p.mother_email or ""
            q.parent1_cell_phone = p.mother_phone or ""
            if p.mother_first_name and not q.parent1_relationship:
                q.parent1_relationship = "Mother"
            q.parent2_first_name = p.father_first_name or ""
            q.parent2_last_name = p.father_last_name or ""
            q.parent2_email = p.father_email or ""
            q.parent2_cell_phone = p.father_phone or ""
            if p.father_first_name and not q.parent2_relationship:
                q.parent2_relationship = "Father"
            offers = [getattr(p, f"offer{i}", "") for i in range(1, 6) if getattr(p, f"offer{i}", "")]
            q.offers = ", ".join(offers)
            q.updated_at = datetime.utcnow()
    else:
        c = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
        if not c:
            c = CoachProfile(user_id=user_id)
            db.add(c)
            db.flush()
        c.first_name = form.get("first_name", "")[:100]
        c.last_name = form.get("last_name", "")[:100]
        # School/college are locked after initial set — admins must change via /admin/users/{id}/edit-profile
        if not (c.school or "").strip():
            c.school = form.get("school", "")[:100]
        if not (c.college or "").strip():
            c.college = form.get("college", "")[:100]
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

    # Evaluations — all logged-in users can see; only coaches/admins can write
    eval_list = []
    can_evaluate = False
    can_view_evals = False
    if target.role == "player" and current_user:
        can_view_evals = True
        if current_user.role == "coach" or current_user.is_admin:
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
    is_coach_viewer = bool(current_user and current_user.role == "coach")
    can_view_photos   = is_owner or is_admin_viewer or is_coach_viewer or tier_gte(pt, "advanced")
    can_view_offers   = is_owner or is_admin_viewer or is_coach_viewer or tier_gte(pt, "advanced")
    can_view_visits   = is_owner or is_admin_viewer or is_coach_viewer or tier_gte(pt, "advanced")
    can_view_videos   = is_owner or is_admin_viewer or is_coach_viewer or tier_gte(pt, "premium")
    can_view_contact  = is_owner or is_admin_viewer or is_coach_viewer or tier_gte(pt, "premium")
    can_message       = bool(not is_owner and (is_admin_viewer or is_coach_viewer))
    # Transcripts: coaches and admins can always view
    if not (is_owner or is_admin_viewer or is_coach_viewer):
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
        "can_view_evals": can_view_evals,
        "can_view_parents": bool(current_user and (current_user.role == "coach" or current_user.is_admin)),
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
        "verified_stats": {vs.stat_field for vs in db.query(VerifiedStat).filter(VerifiedStat.player_id == target.id).all()} if target.role == "player" else set(),
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

    video_id_hex = uuid.uuid4().hex
    key = f"videos/{upload_user_id}/{video_id_hex}.{ext}"
    content_type = video.content_type or f"video/{ext}"
    file_data = video.file

    # Transcode non-mp4 formats (mov, avi, mkv, webm) to mp4 for browser compatibility
    _transcode_cleanup = []
    needs_transcode = ext in ("mov", "avi", "mkv", "webm")
    if needs_transcode:
        import tempfile, subprocess, shutil
        tmp_in = tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False)
        tmp_out = tmp_in.name.rsplit(".", 1)[0] + ".mp4"
        _transcode_cleanup = [tmp_in.name, tmp_out]
        try:
            shutil.copyfileobj(file_data, tmp_in)
            tmp_in.close()
            proc = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["ffmpeg", "-i", tmp_in.name, "-c:v", "libx264", "-preset", "fast",
                     "-crf", "23", "-c:a", "aac", "-movflags", "+faststart", "-y", tmp_out],
                    capture_output=True, timeout=300
                )
            )
            if proc.returncode != 0:
                return RedirectResponse(redirect_to + "?video_error=upload", status_code=302)
            key = f"videos/{upload_user_id}/{video_id_hex}.mp4"
            content_type = "video/mp4"
            file_data = open(tmp_out, "rb")
        except Exception:
            return RedirectResponse(redirect_to + "?video_error=upload", status_code=302)

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
    finally:
        import os as _os
        for _f in _transcode_cleanup:
            try:
                _os.unlink(_f)
            except Exception:
                pass

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
    if current_user.id != t.user_id and not current_user.is_admin and current_user.role != "coach":
        raise HTTPException(status_code=403, detail="Not authorized to view this transcript")
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

@app.get("/profile/transcripts/{transcript_id}/inline")
async def inline_transcript(transcript_id: int, request: Request, db: Session = Depends(get_db)):
    """Serve transcript PDF inline for iframe embedding."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    current_user = db.query(User).filter(User.id == user_id).first()
    if not current_user:
        return RedirectResponse("/login", status_code=302)
    t = db.query(Transcript).filter(Transcript.id == transcript_id).first()
    if not t:
        raise HTTPException(status_code=404)
    if current_user.id != t.user_id and not current_user.is_admin and current_user.role != "coach":
        raise HTTPException(status_code=403)
    key = t.file_url.replace(f"{SPACES_BASE_URL}/", "")
    obj = s3.get_object(Bucket=SPACES_BUCKET, Key=key)
    ext = key.rsplit(".", 1)[-1].lower() if "." in key else "pdf"
    content_type = TRANSCRIPT_CONTENT_TYPES.get(ext, "application/pdf")
    return Response(content=obj["Body"].read(), media_type=content_type)

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
    if current_user.id != t.user_id and not current_user.is_admin and current_user.role != "coach":
        raise HTTPException(status_code=403, detail="Not authorized to view this transcript")
    ext = t.file_url.split("?")[0].rsplit(".", 1)[-1].lower() if "." in t.file_url else "pdf"
    # Redirect to inline endpoint — browser renders PDF natively
    return RedirectResponse(f"/profile/transcripts/{transcript_id}/inline", status_code=302)

    # Dead code below kept for reference
    html = f"""<!DOCTYPE html>
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
    PER_PAGE = 10

    # Coaches pagination
    try:
        coach_page = max(1, int(request.query_params.get("coach_page", "1")))
    except ValueError:
        coach_page = 1
    coach_q = (request.query_params.get("coach_q") or "").strip()
    coach_query = db.query(User).filter(User.role == "coach")
    if coach_q:
        like = f"%{coach_q}%"
        coach_query = coach_query.outerjoin(
            CoachProfile, CoachProfile.user_id == User.id
        ).filter(
            (User.username.ilike(like))
            | (User.email.ilike(like))
            | (CoachProfile.first_name.ilike(like))
            | (CoachProfile.last_name.ilike(like))
            | (CoachProfile.school.ilike(like))
            | (CoachProfile.college.ilike(like))
        )
    total_coaches = coach_query.count()
    coach_total_pages = max(1, (total_coaches + PER_PAGE - 1) // PER_PAGE)
    coach_page = min(coach_page, coach_total_pages)
    coaches_raw = coach_query.order_by(User.username).offset((coach_page - 1) * PER_PAGE).limit(PER_PAGE).all()
    coaches = []
    for c in coaches_raw:
        cp = db.query(CoachProfile).filter(CoachProfile.user_id == c.id).first()
        coaches.append({"user": c, "profile": cp})

    # Players pagination
    try:
        player_page = max(1, int(request.query_params.get("player_page", "1")))
    except ValueError:
        player_page = 1
    player_q = (request.query_params.get("player_q") or "").strip()
    player_tier = (request.query_params.get("player_tier") or "").strip().lower()
    player_query = db.query(User).filter(User.role == "player")
    if player_tier in ("free", "essentials", "advanced", "premium"):
        player_query = player_query.filter(User.subscription_tier == player_tier)
    if player_q:
        like = f"%{player_q}%"
        player_query = player_query.outerjoin(
            PlayerProfile, PlayerProfile.user_id == User.id
        ).filter(
            (User.username.ilike(like))
            | (User.email.ilike(like))
            | (PlayerProfile.first_name.ilike(like))
            | (PlayerProfile.last_name.ilike(like))
            | (PlayerProfile.school.ilike(like))
        )
    total_players = player_query.count()
    total_pages = max(1, (total_players + PER_PAGE - 1) // PER_PAGE)
    player_page = min(player_page, total_pages)
    player_users = player_query.order_by(User.created_at.desc()).offset((player_page - 1) * PER_PAGE).limit(PER_PAGE).all()
    players = []
    for p in player_users:
        prof = db.query(PlayerProfile).filter(PlayerProfile.user_id == p.id).first()
        players.append({"user": p, "profile": prof})

    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("admin_teams.html", {
        "request": request, "user": user,
        "teams": teams, "coaches": coaches, "unread_count": unread_count,
        "success": False, "error": None,
        "players": players,
        "total_players": total_players,
        "player_page": player_page,
        "total_pages": total_pages,
        "player_q": player_q,
        "player_tier": player_tier,
        "total_coaches": total_coaches,
        "coach_page": coach_page,
        "coach_total_pages": coach_total_pages,
        "coach_q": coach_q,
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

    if not name:
        return RedirectResponse("/admin/teams?error=empty_name", status_code=302)
    if db.query(Team).filter(Team.name == name).first():
        return RedirectResponse("/admin/teams?error=duplicate", status_code=302)
    db.add(Team(name=name))
    db.commit()
    return RedirectResponse("/admin/teams?success=1", status_code=302)

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
        "verified_stats": {vs.stat_field for vs in db.query(VerifiedStat).filter(VerifiedStat.player_id == target_id).all()} if target.role == "player" else set(),
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
        p.county = form.get("school_county", "")[:100]
        p.mother_first_name = form.get("mother_first_name", "")[:100]
        p.mother_last_name = form.get("mother_last_name", "")[:100]
        p.mother_email = form.get("mother_email", "")[:200]
        p.mother_phone = form.get("mother_phone", "")[:50]
        p.father_first_name = form.get("father_first_name", "")[:100]
        p.father_last_name = form.get("father_last_name", "")[:100]
        p.father_email = form.get("father_email", "")[:200]
        p.father_phone = form.get("father_phone", "")[:50]
        p.home_address_street = form.get("home_address_street", "")[:200]
        p.home_address_city = form.get("home_address_city", "")[:100]
        p.home_address_state = form.get("home_address_state", "")[:10]
        p.home_address_zip = form.get("home_address_zip", "")[:20]
        for _ni in range(1, 6):
            setattr(p, f"news_link{_ni}", form.get(f"news_link{_ni}", "")[:500])
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
        _allowed_factors = {"location", "winning_tradition", "education", "player_development", "opportunity_to_play", "cost", "school_size", "job_placement", "facilities"}
        _selected = [v for v in form.getlist("biggest_factors") if v in _allowed_factors]
        p.biggest_factors = ",".join(_selected)
    else:
        c = db.query(CoachProfile).filter(CoachProfile.user_id == target_id).first()
        c.first_name = form.get("first_name", "")[:100]
        c.last_name = form.get("last_name", "")[:100]
        c.school = form.get("school", "")[:100]
        c.college = form.get("college", "")[:100]
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
        "verified_stats": {vs.stat_field for vs in db.query(VerifiedStat).filter(VerifiedStat.player_id == target_id).all()} if target.role == "player" else set(),
    })


@app.post("/admin/users/{target_id}/verify-stat", response_class=HTMLResponse)
async def admin_verify_stat(target_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    admin = db.query(User).filter(User.id == user_id).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    form = await request.form()
    stat_field = form.get("stat_field", "")
    allowed_fields = {"height", "weight", "forty_yard", "bench_press", "vertical", "squat", "clean", "broad_jump", "pro_agility", "wingspan", "gpa"}
    if stat_field not in allowed_fields:
        raise HTTPException(status_code=400, detail="Invalid stat field.")
    existing = db.query(VerifiedStat).filter(VerifiedStat.player_id == target_id, VerifiedStat.stat_field == stat_field).first()
    if existing:
        db.delete(existing)
        action_detail = f"unverified {stat_field}"
    else:
        db.add(VerifiedStat(player_id=target_id, stat_field=stat_field, verified_by=admin.id))
        action_detail = f"verified {stat_field}"
    db.commit()
    _ip = request.headers.get("x-real-ip", request.client.host if request.client else "")
    log_admin_action(db, admin.id, "verify_stat", target_id, action_detail, _ip)
    return RedirectResponse(f"/admin/users/{target_id}/edit-profile", status_code=302)

MARKETING_STAGES = ["new", "contacted", "responded", "demo", "onboarded", "inactive"]
MARKETING_STAGE_LABELS = {
    "new": "New",
    "contacted": "Contacted",
    "responded": "Responded",
    "demo": "Demo Scheduled",
    "onboarded": "Onboarded",
    "inactive": "Inactive",
}


def _marketing_require_admin(request: Request, db: Session):
    user_id = request.session.get("user_id")
    if not user_id:
        return None, RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        return None, RedirectResponse("/dashboard", status_code=302)
    return user, None


def _marketing_require_admin_json(request: Request, db: Session):
    user_id = request.session.get("user_id")
    if not user_id:
        return None, JSONResponse({"error": "Not authorized"}, status_code=403)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        return None, JSONResponse({"error": "Not authorized"}, status_code=403)
    return user, None


def _marketing_bulk_ingest(db: Session):
    """Create MarketingLead rows for every coach account and every self-request invite that isn't already in the CRM."""
    existing_emails = {row[0].lower() for row in db.query(MarketingLead.email).all() if row[0]}
    added = 0
    # Coach accounts → leads with stage=onboarded
    coaches = db.query(User).filter(User.role == "coach").all()
    for c in coaches:
        if not c.email or c.email.lower() in existing_emails:
            continue
        cp = db.query(CoachProfile).filter(CoachProfile.user_id == c.id).first()
        lead = MarketingLead(
            name=(f"{cp.first_name or ''} {cp.last_name or ''}".strip() if cp else c.username),
            email=c.email.lower(),
            phone=(cp.phone if cp else "") or "",
            role="coach",
            school=((cp.college or cp.school) if cp else "") or "",
            division=(cp.division if cp else "") or "",
            conference=(cp.conference if cp else "") or "",
            stage="onboarded",
            source="coach_account",
            notes="Auto-imported from existing coach account",
        )
        db.add(lead)
        existing_emails.add(c.email.lower())
        added += 1
    # Self-request invites → leads with stage=contacted
    reqs = db.query(CoachInvite).filter(CoachInvite.source == "self_request").all()
    for inv in reqs:
        em = (inv.requested_email or "").lower().strip()
        if not em or em in existing_emails:
            continue
        lead = MarketingLead(
            name="",
            email=em,
            role="coach",
            school=inv.requested_school or "",
            division=inv.requested_division or "",
            conference=inv.requested_conference or "",
            stage="contacted" if inv.used else "new",
            source="self_request",
            notes=f"Auto-imported from coach access request (invite id {inv.id})",
        )
        db.add(lead)
        existing_emails.add(em)
        added += 1
    if added:
        db.commit()
    return added


@app.get("/admin/marketing", response_class=HTMLResponse)
async def admin_marketing_dashboard(request: Request, db: Session = Depends(get_db)):
    user, err = _marketing_require_admin(request, db)
    if err:
        return err
    _marketing_bulk_ingest(db)

    stage = (request.query_params.get("stage") or "").strip().lower()
    source = (request.query_params.get("source") or "").strip()
    state = (request.query_params.get("state") or "").strip().upper()
    q = (request.query_params.get("q") or "").strip()
    tag = (request.query_params.get("tag") or "").strip().lower()

    query = db.query(MarketingLead)
    if stage and stage in MARKETING_STAGES:
        query = query.filter(MarketingLead.stage == stage)
    if source:
        query = query.filter(MarketingLead.source == source)
    if state:
        query = query.filter(MarketingLead.state == state)
    if q:
        like = f"%{q}%"
        query = query.filter(
            (MarketingLead.name.ilike(like))
            | (MarketingLead.email.ilike(like))
            | (MarketingLead.school.ilike(like))
        )
    if tag:
        query = query.filter(MarketingLead.tags.ilike(f"%{tag}%"))
    leads = query.order_by(MarketingLead.updated_at.desc()).limit(500).all()

    all_leads = db.query(MarketingLead).all()
    stage_counts = {s: 0 for s in MARKETING_STAGES}
    for l in all_leads:
        if l.stage in stage_counts:
            stage_counts[l.stage] += 1

    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    activities_this_week = db.query(MarketingActivity).filter(MarketingActivity.created_at >= week_ago).count()
    signed_up_this_week = db.query(MarketingLead).filter(
        MarketingLead.stage == "onboarded",
        MarketingLead.updated_at >= week_ago,
    ).count()
    responded_count = stage_counts.get("responded", 0) + stage_counts.get("demo", 0) + stage_counts.get("onboarded", 0)
    contacted_denom = responded_count + stage_counts.get("contacted", 0)
    response_rate = (responded_count / contacted_denom * 100.0) if contacted_denom else 0.0

    due_followups = db.query(MarketingLead).filter(
        MarketingLead.next_followup_at != None,
        MarketingLead.next_followup_at <= now,
        MarketingLead.stage != "inactive",
    ).order_by(MarketingLead.next_followup_at.asc()).limit(20).all()

    distinct_sources = sorted({l.source for l in all_leads if l.source})
    distinct_states = sorted({l.state for l in all_leads if l.state})
    admin_list = db.query(User).filter(User.is_admin == True).all()

    return templates.TemplateResponse("marketing_dashboard.html", {
        "request": request,
        "user": user,
        "leads": leads,
        "total_leads": len(all_leads),
        "stage_counts": stage_counts,
        "stage_labels": MARKETING_STAGE_LABELS,
        "activities_this_week": activities_this_week,
        "signed_up_this_week": signed_up_this_week,
        "response_rate": response_rate,
        "due_followups": due_followups,
        "distinct_sources": distinct_sources,
        "distinct_states": distinct_states,
        "admin_list": admin_list,
        "filter_stage": stage,
        "filter_source": source,
        "filter_state": state,
        "filter_q": q,
        "filter_tag": tag,
        "stages": MARKETING_STAGES,
    })


@app.post("/admin/marketing/leads/create")
async def admin_marketing_create(request: Request, db: Session = Depends(get_db)):
    user, err = _marketing_require_admin(request, db)
    if err:
        return err
    form = await request.form()
    email = (form.get("email") or "").strip().lower()
    if not email:
        return RedirectResponse("/admin/marketing?error=email_required", status_code=302)
    existing = db.query(MarketingLead).filter(MarketingLead.email == email).first()
    if existing:
        return RedirectResponse(f"/admin/marketing/leads/{existing.id}", status_code=302)
    lead = MarketingLead(
        name=(form.get("name") or "").strip()[:200],
        email=email[:200],
        phone=(form.get("phone") or "").strip()[:50],
        role=(form.get("role") or "").strip()[:50],
        school=(form.get("school") or "").strip()[:200],
        state=(form.get("state") or "").strip().upper()[:10],
        division=(form.get("division") or "").strip()[:50],
        conference=(form.get("conference") or "").strip()[:100],
        stage=(form.get("stage") or "new").strip().lower()[:20],
        source=(form.get("source") or "manual").strip()[:50],
        tags=(form.get("tags") or "").strip()[:500],
        notes=(form.get("notes") or "").strip()[:5000],
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return RedirectResponse(f"/admin/marketing/leads/{lead.id}", status_code=302)


@app.get("/admin/marketing/leads/{lead_id}", response_class=HTMLResponse)
async def admin_marketing_lead_detail(lead_id: int, request: Request, db: Session = Depends(get_db)):
    user, err = _marketing_require_admin(request, db)
    if err:
        return err
    lead = db.query(MarketingLead).filter(MarketingLead.id == lead_id).first()
    if not lead:
        return RedirectResponse("/admin/marketing", status_code=302)
    activities = db.query(MarketingActivity).filter(
        MarketingActivity.lead_id == lead_id,
    ).order_by(MarketingActivity.created_at.desc()).limit(200).all()
    admin_by_id = {u.id: u.username for u in db.query(User).filter(User.is_admin == True).all()}
    admin_list = db.query(User).filter(User.is_admin == True).all()
    return templates.TemplateResponse("marketing_lead.html", {
        "request": request,
        "user": user,
        "lead": lead,
        "activities": activities,
        "admin_by_id": admin_by_id,
        "admin_list": admin_list,
        "stages": MARKETING_STAGES,
        "stage_labels": MARKETING_STAGE_LABELS,
    })


@app.post("/admin/marketing/leads/{lead_id}/update")
async def admin_marketing_lead_update(lead_id: int, request: Request, db: Session = Depends(get_db)):
    user, err = _marketing_require_admin(request, db)
    if err:
        return err
    lead = db.query(MarketingLead).filter(MarketingLead.id == lead_id).first()
    if not lead:
        return RedirectResponse("/admin/marketing", status_code=302)
    form = await request.form()
    lead.name = (form.get("name") or "").strip()[:200]
    lead.email = (form.get("email") or "").strip().lower()[:200]
    lead.phone = (form.get("phone") or "").strip()[:50]
    lead.role = (form.get("role") or "").strip()[:50]
    lead.school = (form.get("school") or "").strip()[:200]
    lead.state = (form.get("state") or "").strip().upper()[:10]
    lead.division = (form.get("division") or "").strip()[:50]
    lead.conference = (form.get("conference") or "").strip()[:100]
    stage = (form.get("stage") or "new").strip().lower()[:20]
    if stage in MARKETING_STAGES:
        lead.stage = stage
    lead.source = (form.get("source") or "").strip()[:50]
    lead.tags = (form.get("tags") or "").strip()[:500]
    lead.notes = (form.get("notes") or "").strip()[:5000]
    assigned = (form.get("assigned_to") or "").strip()
    lead.assigned_to = int(assigned) if assigned.isdigit() else None
    followup = (form.get("next_followup_at") or "").strip()
    if followup:
        try:
            lead.next_followup_at = datetime.strptime(followup, "%Y-%m-%d")
        except ValueError:
            pass
    else:
        lead.next_followup_at = None
    db.commit()
    return RedirectResponse(f"/admin/marketing/leads/{lead_id}", status_code=302)


@app.post("/admin/marketing/leads/{lead_id}/activity")
async def admin_marketing_lead_activity(lead_id: int, request: Request, db: Session = Depends(get_db)):
    user, err = _marketing_require_admin(request, db)
    if err:
        return err
    lead = db.query(MarketingLead).filter(MarketingLead.id == lead_id).first()
    if not lead:
        return RedirectResponse("/admin/marketing", status_code=302)
    form = await request.form()
    activity = MarketingActivity(
        lead_id=lead_id,
        type=(form.get("type") or "note").strip().lower()[:20],
        direction=(form.get("direction") or "out").strip().lower()[:10],
        subject=(form.get("subject") or "").strip()[:500],
        body=(form.get("body") or "").strip()[:10000],
        created_by=user.id,
    )
    db.add(activity)
    lead.last_contacted_at = datetime.utcnow()
    if lead.stage == "new":
        lead.stage = "contacted"
    db.commit()
    return RedirectResponse(f"/admin/marketing/leads/{lead_id}", status_code=302)


@app.post("/admin/marketing/leads/{lead_id}/send-email")
async def admin_marketing_send_email(lead_id: int, request: Request, db: Session = Depends(get_db)):
    user, err = _marketing_require_admin(request, db)
    if err:
        return err
    lead = db.query(MarketingLead).filter(MarketingLead.id == lead_id).first()
    if not lead or not lead.email:
        return RedirectResponse("/admin/marketing", status_code=302)
    form = await request.form()
    subject = (form.get("subject") or "").strip()[:500]
    body = (form.get("body") or "").strip()[:20000]
    if not subject or not body:
        return RedirectResponse(f"/admin/marketing/leads/{lead_id}?error=email_missing_fields", status_code=302)
    # Queue send
    async def _do_send():
        try:
            import aiosmtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"CAP Recruiting <{SMTP_USER}>"
            msg["To"] = lead.email
            html_body = body.replace("\n", "<br>")
            msg.attach(MIMEText(html_body, "html"))
            await aiosmtplib.send(msg, hostname=SMTP_HOST, port=SMTP_PORT, username=SMTP_USER, password=SMTP_PASSWORD, start_tls=True)
        except Exception as e:
            _logger.warning("Marketing email send failed: %s", type(e).__name__)
    asyncio.create_task(_do_send())
    # Log activity
    act = MarketingActivity(
        lead_id=lead_id,
        type="email",
        direction="out",
        subject=subject,
        body=body,
        created_by=user.id,
    )
    db.add(act)
    lead.last_contacted_at = datetime.utcnow()
    if lead.stage == "new":
        lead.stage = "contacted"
    db.commit()
    return RedirectResponse(f"/admin/marketing/leads/{lead_id}?sent=1", status_code=302)


@app.post("/admin/marketing/leads/{lead_id}/delete")
async def admin_marketing_lead_delete(lead_id: int, request: Request, db: Session = Depends(get_db)):
    user, err = _marketing_require_admin(request, db)
    if err:
        return err
    lead = db.query(MarketingLead).filter(MarketingLead.id == lead_id).first()
    if not lead:
        return RedirectResponse("/admin/marketing", status_code=302)
    db.query(MarketingActivity).filter(MarketingActivity.lead_id == lead_id).delete()
    db.delete(lead)
    db.commit()
    return RedirectResponse("/admin/marketing", status_code=302)


@app.post("/admin/marketing/leads/import")
async def admin_marketing_import(request: Request, db: Session = Depends(get_db)):
    user, err = _marketing_require_admin(request, db)
    if err:
        return err
    form = await request.form()
    raw = (form.get("csv") or "").strip()
    if not raw:
        return RedirectResponse("/admin/marketing?error=csv_empty", status_code=302)
    reader = csv.DictReader(io.StringIO(raw))
    added = 0
    updated = 0
    for row in reader:
        email = (row.get("email") or row.get("Email") or "").strip().lower()
        if not email:
            continue
        existing = db.query(MarketingLead).filter(MarketingLead.email == email).first()
        fields = {
            "name": (row.get("name") or row.get("Name") or "").strip()[:200],
            "phone": (row.get("phone") or row.get("Phone") or "").strip()[:50],
            "role": (row.get("role") or row.get("Role") or "").strip().lower()[:50],
            "school": (row.get("school") or row.get("School") or "").strip()[:200],
            "state": (row.get("state") or row.get("State") or "").strip().upper()[:10],
            "division": (row.get("division") or row.get("Division") or "").strip()[:50],
            "conference": (row.get("conference") or row.get("Conference") or "").strip()[:100],
            "tags": (row.get("tags") or row.get("Tags") or "").strip()[:500],
            "notes": (row.get("notes") or row.get("Notes") or "").strip()[:5000],
        }
        if existing:
            for k, v in fields.items():
                if v:
                    setattr(existing, k, v)
            updated += 1
        else:
            lead = MarketingLead(
                email=email,
                stage="new",
                source="csv",
                **fields,
            )
            db.add(lead)
            added += 1
    db.commit()
    return RedirectResponse(f"/admin/marketing?imported={added}&updated={updated}", status_code=302)


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
    if _check_rate_limit(f"msg:{user_id}", 30, 60):
        return JSONResponse({"error": "Slow down — too many messages."}, status_code=429)
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
    request.session["subscription_tier"] = user.subscription_tier or "free"
    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("questionnaires.html", {
        "request": request,
        "user": user,
        "unread_count": unread_count,
        "data": QUESTIONNAIRE_DATA,
        "is_premium": tier_gte(user.subscription_tier or "free", "premium"),
    })

@app.get("/my-questionnaire", response_class=HTMLResponse)
async def my_questionnaire_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role != "player":
        return RedirectResponse("/dashboard", status_code=302)
    if not tier_gte(user.subscription_tier or "free", "premium"):
        return RedirectResponse("/upgrade", status_code=302)
    profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
    q = db.query(PlayerQuestionnaire).filter(PlayerQuestionnaire.user_id == user_id).first()
    if not q:
        # Create questionnaire and auto-populate from profile
        q = PlayerQuestionnaire(user_id=user_id)
        if profile:
            q.email = user.email or ""
            q.cell_phone = profile.phone or ""
            q.address_street = profile.home_address_street or ""
            q.address_city = profile.home_address_city or ""
            q.address_state = profile.home_address_state or ""
            q.address_zip = profile.home_address_zip or ""
            q.school_name = profile.school or ""
            q.school_city = profile.city or ""
            q.school_state = profile.state or ""
            q.gpa = profile.gpa or ""
            q.intended_major = profile.intended_major or ""
            q.ncaa_eligibility_id = profile.ncaa_eligibility_num or ""
            q.height = profile.height or ""
            q.weight = profile.weight or ""
            q.position_offense = profile.position or ""
            q.forty_yard = profile.forty_yard or ""
            q.bench_press = profile.bench_press or ""
            q.squat = profile.squat or ""
            q.powerclean = profile.clean or ""
            q.vertical = profile.vertical or ""
            q.broad_jump = profile.broad_jump or ""
            q.wingspan = profile.wingspan or ""
            q.hudl_link = profile.hudl_url or ""
            q.twitter = profile.x_url or ""
            q.instagram = profile.instagram_url or ""
            q.grad_year = profile.year or ""
            q.parent1_first_name = profile.mother_first_name or ""
            q.parent1_last_name = profile.mother_last_name or ""
            q.parent1_email = profile.mother_email or ""
            q.parent1_cell_phone = profile.mother_phone or ""
            q.parent1_relationship = "Mother" if profile.mother_first_name else ""
            q.parent2_first_name = profile.father_first_name or ""
            q.parent2_last_name = profile.father_last_name or ""
            q.parent2_email = profile.father_email or ""
            q.parent2_cell_phone = profile.father_phone or ""
            q.parent2_relationship = "Father" if profile.father_first_name else ""
            # Populate offers
            offers = []
            for i in range(1, 6):
                o = getattr(profile, f"offer{i}", "")
                if o:
                    offers.append(o)
            q.offers = ", ".join(offers)
            # Film link
            q.film_link = profile.hudl_url or ""
        db.add(q)
        db.commit()
        db.refresh(q)
    request.session["subscription_tier"] = user.subscription_tier or "free"
    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("my_questionnaire.html", {
        "request": request,
        "user": user,
        "profile": profile,
        "q": q,
        "unread_count": unread_count,
    })

@app.post("/my-questionnaire/save")
async def save_questionnaire_field(request: Request, db: Session = Depends(get_db)):
    """Auto-save individual questionnaire fields via AJAX."""
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "Not logged in"}, status_code=401)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not tier_gte(user.subscription_tier or "free", "premium"):
        return JSONResponse({"error": "Premium required"}, status_code=403)
    q = db.query(PlayerQuestionnaire).filter(PlayerQuestionnaire.user_id == user_id).first()
    if not q:
        return JSONResponse({"error": "Questionnaire not found"}, status_code=404)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid request"}, status_code=400)
    field = data.get("field", "")
    value = data.get("value", "")
    # Only allow updating known questionnaire columns
    allowed = {c.name for c in PlayerQuestionnaire.__table__.columns} - {"id", "user_id", "updated_at"}
    if field not in allowed:
        return JSONResponse({"error": "Invalid field"}, status_code=400)
    setattr(q, field, value[:2000])
    q.updated_at = datetime.utcnow()
    db.commit()
    return JSONResponse({"ok": True})

@app.get("/my-questionnaire/pdf")
async def download_questionnaire_pdf(request: Request, db: Session = Depends(get_db)):
    """Generate and download questionnaire as PDF."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not tier_gte(user.subscription_tier or "free", "premium"):
        return RedirectResponse("/upgrade", status_code=302)
    q = db.query(PlayerQuestionnaire).filter(PlayerQuestionnaire.user_id == user_id).first()
    profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
    if not q:
        return RedirectResponse("/my-questionnaire", status_code=302)

    full_name = f"{profile.first_name} {profile.last_name}".strip() if profile else user.username

    # Build PDF using reportlab
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    import io

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch, leftMargin=0.6*inch, rightMargin=0.6*inch)
    styles = getSampleStyleSheet()
    elements = []

    # Header
    header_style = ParagraphStyle("Header", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#0a1628"), spaceAfter=4)
    sub_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#6b7280"), spaceAfter=16)
    section_style = ParagraphStyle("Section", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#0a1628"), spaceBefore=16, spaceAfter=8, borderWidth=0)
    label_style = ParagraphStyle("Label", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#6b7280"))
    value_style = ParagraphStyle("Value", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#0a1628"))

    elements.append(Paragraph("Collegiate Athletic Planning", header_style))
    elements.append(Paragraph(f"Recruiting Questionnaire — {full_name}", sub_style))

    def add_section(title, fields):
        elements.append(Paragraph(title, section_style))
        data = []
        row = []
        for label, val in fields:
            row.append([Paragraph(label, label_style), Paragraph(str(val or "—"), value_style)])
            if len(row) == 2:
                data.append(row)
                row = []
        if row:
            row.append(["", ""])
            data.append(row)
        for r in data:
            t = Table([[r[0][0], r[0][1], r[1][0], r[1][1]]], colWidths=[1.4*inch, 2.1*inch, 1.4*inch, 2.1*inch])
            t.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
            ]))
            elements.append(t)

    add_section("Personal Information", [
        ("First Name", profile.first_name if profile else ""),
        ("Last Name", profile.last_name if profile else ""),
        ("Preferred Name", q.preferred_name),
        ("Middle Name", q.middle_name),
        ("Date of Birth", q.date_of_birth),
        ("Email", q.email),
        ("Cell Phone", q.cell_phone),
        ("Home Phone", q.home_phone),
        ("Best Time to Call", q.best_time_to_call),
        ("Street Address", q.address_street),
        ("City", q.address_city),
        ("State", q.address_state),
        ("Zip", q.address_zip),
        ("Twitter / X", q.twitter),
        ("Instagram", q.instagram),
        ("Facebook", q.facebook),
    ])

    add_section("Academic Information", [
        ("High School", q.school_name),
        ("School City", q.school_city),
        ("School State", q.school_state),
        ("School Zip", q.school_zip),
        ("School Phone", q.school_phone),
        ("School Fax", q.school_fax),
        ("Counselor Name", q.counselor_name),
        ("Counselor Email", q.counselor_email),
        ("Counselor Phone", q.counselor_phone),
        ("Grad Year", q.grad_year),
        ("GPA", q.gpa),
        ("SAT Composite", q.sat_composite),
        ("SAT Math", q.sat_math),
        ("SAT Reading", q.sat_reading),
        ("ACT Composite", q.act_composite),
        ("Intended Major", q.intended_major),
        ("NCAA Eligibility", q.ncaa_eligibility),
        ("NCAA ID", q.ncaa_eligibility_id),
    ])

    add_section("Athletic Information", [
        ("Height", q.height),
        ("Weight", q.weight),
        ("Position (Offense)", q.position_offense),
        ("Position (Defense)", q.position_defense),
        ("Position (Special Teams)", q.position_special_teams),
        ("Jersey #", q.jersey_number),
        ("40 Yard Dash", q.forty_yard),
        ("Pro Agility / Shuttle", q.shuttle),
        ("Vertical Jump", q.vertical),
        ("Broad Jump", q.broad_jump),
        ("Bench Press", q.bench_press),
        ("Squat", q.squat),
        ("Power Clean", q.powerclean),
        ("Wingspan", q.wingspan),
        ("Other Sports", q.other_sports),
        ("HUDL Link", q.hudl_link),
        ("Film Link", q.film_link),
    ])

    add_section("Parent / Guardian 1", [
        ("First Name", q.parent1_first_name),
        ("Last Name", q.parent1_last_name),
        ("Relationship", q.parent1_relationship),
        ("Email", q.parent1_email),
        ("Cell Phone", q.parent1_cell_phone),
        ("Business Phone", q.parent1_business_phone),
        ("Occupation", q.parent1_occupation),
        ("College", q.parent1_college),
        ("Address (if different)", q.parent1_address),
    ])

    add_section("Parent / Guardian 2", [
        ("First Name", q.parent2_first_name),
        ("Last Name", q.parent2_last_name),
        ("Relationship", q.parent2_relationship),
        ("Email", q.parent2_email),
        ("Cell Phone", q.parent2_cell_phone),
        ("Business Phone", q.parent2_business_phone),
        ("Occupation", q.parent2_occupation),
        ("College", q.parent2_college),
        ("Address (if different)", q.parent2_address),
    ])

    add_section("Family & Influences", [
        ("Siblings", q.siblings),
        ("Influential Person 1", q.influential_person1),
        ("Influential Person 2", q.influential_person2),
    ])

    add_section("Club / Travel Team", [
        ("Club / Team Name", q.club_team_name),
        ("Club Coach Name", q.club_coach_name),
        ("Club Coach Email", q.club_coach_email),
        ("Club Coach Phone", q.club_coach_phone),
    ])

    add_section("High School Coaching Staff", [
        ("Head Coach Name", q.head_coach_name),
        ("Head Coach Phone", q.head_coach_phone),
        ("Head Coach Email", q.head_coach_email),
        ("School Fax", q.school_fax),
    ])

    add_section("Recruitment", [
        ("Top Schools", q.top_schools),
        ("Offers", q.offers),
        ("Connection to School", q.connection_to_school),
        ("Campus Visits (completed)", q.campus_visits),
        ("Planned Visits", q.planned_visits),
        ("Decision Timeline", q.decision_timeline),
    ])

    if q.athletic_achievements:
        elements.append(Paragraph("Athletic Achievements", section_style))
        elements.append(Paragraph(q.athletic_achievements or "—", value_style))

    if q.injuries:
        elements.append(Paragraph("Injuries / Surgeries", section_style))
        elements.append(Paragraph(q.injuries or "—", value_style))

    doc.build(elements)
    buf.seek(0)
    filename = f"CAP_Questionnaire_{full_name.replace(' ', '_')}.pdf"
    return Response(
        content=buf.read(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# ── Scout Board (Coach Dashboard) ─────────────────────────────────────────────
DEFAULT_LANES = ["Watching", "Contacted", "Evaluating", "Offered", "Committed"]

def _coach_college(user: "User", db: Session) -> str:
    """Get the college a coach is associated with."""
    if not user or user.role != "coach":
        return ""
    cp = db.query(CoachProfile).filter(CoachProfile.user_id == user.id).first()
    return (cp.college or cp.school or "").strip() if cp else ""

def _ensure_default_lanes(college: str, db: Session):
    """Create default lanes for a college if none exist."""
    existing = db.query(ScoutBoardLane).filter(ScoutBoardLane.college == college).count()
    if existing == 0:
        for idx, name in enumerate(DEFAULT_LANES):
            db.add(ScoutBoardLane(college=college, name=name, sort_order=idx))
        db.commit()

@app.get("/dashboard/scout", response_class=HTMLResponse)
async def scout_board_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or (user.role != "coach" and not user.is_admin):
        return RedirectResponse("/dashboard", status_code=302)
    college = _coach_college(user, db)
    if not college:
        return templates.TemplateResponse("scout_board.html", {
            "request": request, "user": user, "college": "",
            "lanes": [], "cards_by_lane": {}, "scouts": [],
            "needs_college": True,
        })
    _ensure_default_lanes(college, db)
    lanes = db.query(ScoutBoardLane).filter(ScoutBoardLane.college == college).order_by(ScoutBoardLane.sort_order).all()
    cards = db.query(ScoutBoardCard).filter(ScoutBoardCard.college == college, ScoutBoardCard.archived_at.is_(None)).order_by(ScoutBoardCard.sort_order).all()
    cards_by_lane = {lane.id: [] for lane in lanes}
    from sqlalchemy import text as _text
    for c in cards:
        if c.lane_id in cards_by_lane:
            # Resolve player info
            city = ""
            state = ""
            if c.player_user_id:
                p_user = db.query(User).filter(User.id == c.player_user_id).first()
                p_profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == c.player_user_id).first() if p_user else None
                display_name = f"{p_profile.first_name} {p_profile.last_name}".strip() if p_profile and (p_profile.first_name or p_profile.last_name) else (p_user.username if p_user else "Unknown")
                high_school = p_profile.school if p_profile else ""
                position = p_profile.position if p_profile else ""
                photo = c.tile_image_url or (p_profile.photo if p_profile else "")
                if p_profile:
                    city = p_profile.city or ""
                    state = p_profile.state or ""
            else:
                display_name = f"{c.custom_first_name} {c.custom_last_name}".strip()
                high_school = c.custom_high_school
                position = c.custom_position
                photo = c.tile_image_url
                if high_school:
                    row = db.execute(_text("SELECT city, state FROM schools WHERE name = :n LIMIT 1"), {"n": high_school}).fetchone()
                    if row:
                        city = row[0] or ""
                        state = row[1] or ""
            cards_by_lane[c.lane_id].append({
                "id": c.id,
                "name": display_name,
                "high_school": high_school,
                "city": city,
                "state": state,
                "position": position,
                "visit_date": c.visit_date,
                "scout_name": c.scout_name,
                "photo": photo,
                "is_custom": not c.player_user_id,
                "player_user_id": c.player_user_id,
            })
    scouts = db.query(ScoutBoardScout).filter(ScoutBoardScout.college == college).order_by(ScoutBoardScout.last_name).all()
    return templates.TemplateResponse("scout_board.html", {
        "request": request, "user": user, "college": college,
        "lanes": lanes, "cards_by_lane": cards_by_lane, "scouts": scouts,
        "needs_college": False,
    })

@app.post("/dashboard/scout/lane")
async def scout_create_lane(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    if not college:
        return JSONResponse({"error": "No college assigned"}, status_code=400)
    data = await request.json()
    name = (data.get("name") or "").strip()[:50]
    if not name:
        return JSONResponse({"error": "Name required"}, status_code=400)
    count = db.query(ScoutBoardLane).filter(ScoutBoardLane.college == college).count()
    if count >= 5:
        return JSONResponse({"error": "Maximum 5 swimlanes"}, status_code=400)
    lane = ScoutBoardLane(college=college, name=name, sort_order=count)
    db.add(lane)
    db.commit()
    db.refresh(lane)
    return JSONResponse({"ok": True, "id": lane.id, "name": lane.name})

@app.post("/dashboard/scout/lane/{lane_id}/rename")
async def scout_rename_lane(lane_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    lane = db.query(ScoutBoardLane).filter(ScoutBoardLane.id == lane_id, ScoutBoardLane.college == college).first()
    if not lane:
        return JSONResponse({"error": "Not found"}, status_code=404)
    data = await request.json()
    name = (data.get("name") or "").strip()[:50]
    if not name:
        return JSONResponse({"error": "Name required"}, status_code=400)
    lane.name = name
    db.commit()
    return JSONResponse({"ok": True})

@app.post("/dashboard/scout/lane/{lane_id}/delete")
async def scout_delete_lane(lane_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    lane = db.query(ScoutBoardLane).filter(ScoutBoardLane.id == lane_id, ScoutBoardLane.college == college).first()
    if not lane:
        return JSONResponse({"error": "Not found"}, status_code=404)
    # Delete all cards in this lane first
    db.query(ScoutBoardCard).filter(ScoutBoardCard.lane_id == lane_id).delete()
    db.delete(lane)
    db.commit()
    return JSONResponse({"ok": True})

@app.post("/dashboard/scout/card")
async def scout_create_card(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    if not college:
        return JSONResponse({"error": "No college assigned"}, status_code=400)
    data = await request.json()
    lane_id = int(data.get("lane_id", 0))
    lane = db.query(ScoutBoardLane).filter(ScoutBoardLane.id == lane_id, ScoutBoardLane.college == college).first()
    if not lane:
        return JSONResponse({"error": "Invalid lane"}, status_code=400)
    player_user_id = int(data["player_user_id"]) if data.get("player_user_id") else None
    if player_user_id:
        existing = db.query(ScoutBoardCard).filter(
            ScoutBoardCard.college == college,
            ScoutBoardCard.player_user_id == player_user_id,
            ScoutBoardCard.archived_at.is_(None),
        ).first()
        if existing:
            return JSONResponse({"error": "This player is already on your board."}, status_code=400)
    count = db.query(ScoutBoardCard).filter(ScoutBoardCard.lane_id == lane_id).count()
    card = ScoutBoardCard(
        college=college,
        lane_id=lane_id,
        sort_order=count,
        player_user_id=player_user_id,
        custom_first_name=(data.get("custom_first_name") or "")[:100],
        custom_last_name=(data.get("custom_last_name") or "")[:100],
        custom_high_school=(data.get("custom_high_school") or "")[:200],
        custom_grad_year=(data.get("custom_grad_year") or "")[:10],
        custom_position=(data.get("custom_position") or "")[:20],
        visit_date=(data.get("visit_date") or "")[:50],
        scout_name=(data.get("scout_name") or "")[:200],
        notes=(data.get("notes") or "")[:5000],
        created_by=user.id,
    )
    db.add(card)
    db.commit()
    db.refresh(card)
    return JSONResponse({"ok": True, "id": card.id})

@app.get("/dashboard/scout/card/{card_id}")
async def scout_get_card(card_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    card = db.query(ScoutBoardCard).filter(ScoutBoardCard.id == card_id, ScoutBoardCard.college == college).first()
    if not card:
        return JSONResponse({"error": "Not found"}, status_code=404)
    # Resolve player info
    has_questionnaire = False
    if card.player_user_id:
        p_user = db.query(User).filter(User.id == card.player_user_id).first()
        p_profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == card.player_user_id).first() if p_user else None
        first_name = p_profile.first_name if p_profile else ""
        last_name = p_profile.last_name if p_profile else ""
        high_school = p_profile.school if p_profile else ""
        position = p_profile.position if p_profile else ""
        grad_year = p_profile.year if p_profile else ""
        height = p_profile.height if p_profile else ""
        weight = p_profile.weight if p_profile else ""
        photo = card.tile_image_url or (p_profile.photo if p_profile else "")
        profile_username = p_user.username if p_user else ""
        has_questionnaire = db.query(PlayerQuestionnaire.id).filter(PlayerQuestionnaire.user_id == card.player_user_id).first() is not None
    else:
        first_name = card.custom_first_name
        last_name = card.custom_last_name
        high_school = card.custom_high_school
        position = card.custom_position
        grad_year = card.custom_grad_year
        height = ""
        weight = ""
        photo = card.tile_image_url
        profile_username = ""
    return JSONResponse({
        "id": card.id,
        "is_custom": not card.player_user_id,
        "profile_username": profile_username,
        "first_name": first_name,
        "last_name": last_name,
        "high_school": high_school,
        "position": position,
        "grad_year": grad_year,
        "height": height,
        "weight": weight,
        "photo": photo,
        "visit_date": card.visit_date,
        "high_school_visit_date": card.high_school_visit_date,
        "scout_name": card.scout_name,
        "notes": card.notes,
        "lane_id": card.lane_id,
        "has_questionnaire": has_questionnaire,
    })

@app.post("/dashboard/scout/card/{card_id}/update")
async def scout_update_card(card_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    card = db.query(ScoutBoardCard).filter(ScoutBoardCard.id == card_id, ScoutBoardCard.college == college).first()
    if not card:
        return JSONResponse({"error": "Not found"}, status_code=404)
    data = await request.json()
    if "lane_id" in data:
        try:
            new_lane_id = int(data.get("lane_id"))
        except (TypeError, ValueError):
            new_lane_id = None
        if new_lane_id and new_lane_id != card.lane_id:
            new_lane = db.query(ScoutBoardLane).filter(ScoutBoardLane.id == new_lane_id, ScoutBoardLane.college == college).first()
            if new_lane:
                card.lane_id = new_lane_id
                card.sort_order = db.query(ScoutBoardCard).filter(ScoutBoardCard.lane_id == new_lane_id, ScoutBoardCard.archived_at.is_(None)).count()
    if "visit_date" in data:
        card.visit_date = (data.get("visit_date") or "")[:50]
    if "high_school_visit_date" in data:
        card.high_school_visit_date = (data.get("high_school_visit_date") or "")[:50]
    if "scout_name" in data:
        card.scout_name = (data.get("scout_name") or "")[:200]
    if "notes" in data:
        card.notes = (data.get("notes") or "")[:5000]
    if card.player_user_id is None:
        if "custom_first_name" in data:
            card.custom_first_name = (data.get("custom_first_name") or "")[:100]
        if "custom_last_name" in data:
            card.custom_last_name = (data.get("custom_last_name") or "")[:100]
        if "custom_high_school" in data:
            card.custom_high_school = (data.get("custom_high_school") or "")[:200]
        if "custom_position" in data:
            card.custom_position = (data.get("custom_position") or "")[:20]
    db.commit()
    return JSONResponse({"ok": True})

@app.post("/dashboard/scout/card/{card_id}/archive")
async def scout_archive_card(card_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    card = db.query(ScoutBoardCard).filter(ScoutBoardCard.id == card_id, ScoutBoardCard.college == college).first()
    if not card:
        return JSONResponse({"error": "Not found"}, status_code=404)
    card.archived_at = datetime.utcnow()
    card.archived_by = user.id
    db.commit()
    return JSONResponse({"ok": True})

@app.post("/dashboard/scout/card/{card_id}/restore")
async def scout_restore_card(card_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    card = db.query(ScoutBoardCard).filter(ScoutBoardCard.id == card_id, ScoutBoardCard.college == college).first()
    if not card:
        return JSONResponse({"error": "Not found"}, status_code=404)
    lane = db.query(ScoutBoardLane).filter(ScoutBoardLane.id == card.lane_id, ScoutBoardLane.college == college).first()
    if not lane:
        _ensure_default_lanes(college, db)
        lane = db.query(ScoutBoardLane).filter(ScoutBoardLane.college == college).order_by(ScoutBoardLane.sort_order).first()
        if lane:
            card.lane_id = lane.id
    card.archived_at = None
    card.archived_by = None
    count = db.query(ScoutBoardCard).filter(ScoutBoardCard.lane_id == card.lane_id, ScoutBoardCard.archived_at.is_(None)).count()
    card.sort_order = count
    db.commit()
    return JSONResponse({"ok": True})

@app.get("/dashboard/scout/export.csv")
async def scout_export_csv(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    if not college:
        return JSONResponse({"error": "No college assigned"}, status_code=400)
    lanes = {l.id: l for l in db.query(ScoutBoardLane).filter(ScoutBoardLane.college == college).all()}
    cards = db.query(ScoutBoardCard).filter(
        ScoutBoardCard.college == college,
        ScoutBoardCard.archived_at.is_(None),
    ).order_by(ScoutBoardCard.lane_id, ScoutBoardCard.sort_order).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Name", "Position", "High School", "Grad Year", "Height", "Weight",
        "Lane", "Campus Visit Date", "HS Visit Date", "Scout", "Notes", "Created At",
    ])
    for c in cards:
        if c.player_user_id:
            p_user = db.query(User).filter(User.id == c.player_user_id).first()
            p_profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == c.player_user_id).first() if p_user else None
            name = f"{p_profile.first_name} {p_profile.last_name}".strip() if p_profile and (p_profile.first_name or p_profile.last_name) else (p_user.username if p_user else "Unknown")
            position = p_profile.position if p_profile else ""
            high_school = p_profile.school if p_profile else ""
            grad_year = p_profile.year if p_profile else ""
            height = p_profile.height if p_profile else ""
            weight = p_profile.weight if p_profile else ""
        else:
            name = f"{c.custom_first_name} {c.custom_last_name}".strip()
            position = c.custom_position
            high_school = c.custom_high_school
            grad_year = c.custom_grad_year
            height = ""
            weight = ""
        lane = lanes.get(c.lane_id)
        writer.writerow([
            name or "Unnamed",
            position or "",
            high_school or "",
            grad_year or "",
            height or "",
            weight or "",
            lane.name if lane else "",
            c.visit_date or "",
            c.high_school_visit_date or "",
            c.scout_name or "",
            (c.notes or "").replace("\r\n", "\n"),
            c.created_at.strftime("%Y-%m-%d %H:%M") if c.created_at else "",
        ])
    filename = f"scout-board-{college.replace(' ', '_')}-{datetime.utcnow().strftime('%Y%m%d')}.csv"
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.get("/questionnaires/view", response_class=HTMLResponse)
async def questionnaires_view_list(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or (user.role != "coach" and not user.is_admin):
        return RedirectResponse("/dashboard", status_code=302)
    college = _coach_college(user, db)
    on_board_ids = set()
    if college:
        rows_cards = db.query(ScoutBoardCard.player_user_id).filter(
            ScoutBoardCard.college == college,
            ScoutBoardCard.player_user_id.isnot(None),
            ScoutBoardCard.archived_at.is_(None),
        ).all()
        on_board_ids = {r[0] for r in rows_cards if r[0]}
    rows = db.query(PlayerQuestionnaire, User, PlayerProfile).join(
        User, User.id == PlayerQuestionnaire.user_id
    ).outerjoin(
        PlayerProfile, PlayerProfile.user_id == PlayerQuestionnaire.user_id
    ).all()
    on_board_players = []
    groups = {}
    for q, u, p in rows:
        if u.role != "player":
            continue
        display_name = ""
        if p and (p.first_name or p.last_name):
            display_name = f"{p.first_name or ''} {p.last_name or ''}".strip()
        if not display_name:
            display_name = u.username
        entry = {
            "username": u.username,
            "name": display_name,
            "school": (p.school if p else "") or "",
            "position": (p.position if p else "") or "",
            "grad_year": (p.year if p else "") or "",
            "updated_at": q.updated_at,
        }
        if u.id in on_board_ids:
            on_board_players.append(entry)
        else:
            school = (entry["school"] or "").strip() or "Unknown School"
            groups.setdefault(school, []).append(entry)
    on_board_players.sort(key=lambda r: r["name"].lower())
    for school in groups:
        groups[school].sort(key=lambda r: r["name"].lower())
    sorted_schools = sorted(groups.keys(), key=lambda s: (s == "Unknown School", s.lower()))
    return templates.TemplateResponse("questionnaires_list.html", {
        "request": request, "user": user,
        "on_board_players": on_board_players,
        "schools": [(s, groups[s]) for s in sorted_schools],
        "total": len(on_board_players) + sum(len(v) for v in groups.values()),
    })

@app.get("/questionnaires/view/{username}", response_class=HTMLResponse)
async def questionnaires_view_detail(username: str, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    viewer = db.query(User).filter(User.id == user_id).first()
    if not viewer or (viewer.role != "coach" and not viewer.is_admin):
        return RedirectResponse("/dashboard", status_code=302)
    target = db.query(User).filter(User.username == username).first()
    if not target or target.role != "player":
        raise HTTPException(status_code=404, detail="Player not found")
    q = db.query(PlayerQuestionnaire).filter(PlayerQuestionnaire.user_id == target.id).first()
    if not q:
        raise HTTPException(status_code=404, detail="No questionnaire on file")
    profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == target.id).first()
    return templates.TemplateResponse("questionnaire_detail.html", {
        "request": request, "user": viewer, "target": target, "q": q, "profile": profile,
    })

@app.get("/dashboard/scout/archived")
async def scout_list_archived(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    if not college:
        return JSONResponse({"cards": []})
    cards = db.query(ScoutBoardCard).filter(
        ScoutBoardCard.college == college,
        ScoutBoardCard.archived_at.isnot(None),
    ).order_by(ScoutBoardCard.archived_at.desc()).all()
    lanes = {l.id: l.name for l in db.query(ScoutBoardLane).filter(ScoutBoardLane.college == college).all()}
    result = []
    for c in cards:
        if c.player_user_id:
            p_user = db.query(User).filter(User.id == c.player_user_id).first()
            p_profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == c.player_user_id).first() if p_user else None
            name = f"{p_profile.first_name} {p_profile.last_name}".strip() if p_profile and (p_profile.first_name or p_profile.last_name) else (p_user.username if p_user else "Unknown")
            high_school = p_profile.school if p_profile else ""
            position = p_profile.position if p_profile else ""
            photo = c.tile_image_url or (p_profile.photo if p_profile else "")
        else:
            name = f"{c.custom_first_name} {c.custom_last_name}".strip()
            high_school = c.custom_high_school
            position = c.custom_position
            photo = c.tile_image_url
        archiver_name = ""
        if c.archived_by:
            archiver = db.query(User).filter(User.id == c.archived_by).first()
            if archiver:
                cp = db.query(CoachProfile).filter(CoachProfile.user_id == archiver.id).first()
                if cp and (cp.first_name or cp.last_name):
                    archiver_name = f"{cp.first_name} {cp.last_name}".strip()
                else:
                    archiver_name = archiver.username
        result.append({
            "id": c.id,
            "name": name or "Unnamed",
            "high_school": high_school,
            "position": position,
            "photo": photo,
            "lane_name": lanes.get(c.lane_id, ""),
            "archived_at": c.archived_at.isoformat() if c.archived_at else "",
            "archived_by": archiver_name,
        })
    return JSONResponse({"cards": result})

@app.post("/dashboard/scout/reorder")
async def scout_reorder_cards(request: Request, db: Session = Depends(get_db)):
    """Accept array of {card_id, lane_id, sort_order} to update positions after drag/drop."""
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    data = await request.json()
    items = data.get("items", [])
    for item in items:
        card = db.query(ScoutBoardCard).filter(ScoutBoardCard.id == int(item["card_id"]), ScoutBoardCard.college == college).first()
        if card:
            card.lane_id = int(item["lane_id"])
            card.sort_order = int(item["sort_order"])
    db.commit()
    return JSONResponse({"ok": True})

@app.post("/dashboard/scout/card/{card_id}/image")
async def scout_upload_card_image(card_id: int, request: Request, image: UploadFile = File(...), db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    card = db.query(ScoutBoardCard).filter(ScoutBoardCard.id == card_id, ScoutBoardCard.college == college).first()
    if not card:
        return JSONResponse({"error": "Not found"}, status_code=404)
    ext = image.filename.rsplit(".", 1)[-1].lower() if "." in image.filename else "jpg"
    if ext not in ("jpg", "jpeg", "png", "gif", "webp"):
        return JSONResponse({"error": "Invalid file type"}, status_code=400)
    key = f"scout_board/{card.college.replace(' ', '_')}/{uuid.uuid4().hex}.{ext}"
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: s3.upload_fileobj(image.file, SPACES_BUCKET, key, ExtraArgs={"ContentType": image.content_type or f"image/{ext}", "ACL": "public-read"})
        )
    except Exception as e:
        return JSONResponse({"error": f"Upload failed: {e}"}, status_code=500)
    card.tile_image_url = f"{SPACES_BASE_URL}/{key}"
    db.commit()
    return JSONResponse({"ok": True, "url": card.tile_image_url})

@app.post("/dashboard/scout/scout")
async def scout_create_scout(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    college = _coach_college(user, db)
    if not college:
        return JSONResponse({"error": "No college assigned"}, status_code=400)
    data = await request.json()
    first_name = (data.get("first_name") or "").strip()[:100]
    last_name = (data.get("last_name") or "").strip()[:100]
    if not first_name or not last_name:
        return JSONResponse({"error": "First and last name required"}, status_code=400)
    scout = ScoutBoardScout(college=college, first_name=first_name, last_name=last_name)
    db.add(scout)
    db.commit()
    db.refresh(scout)
    return JSONResponse({"ok": True, "id": scout.id, "name": f"{first_name} {last_name}"})

ALL_COLLEGES = [
    "Abilene Christian", "Adams State", "Adrian", "Air Force", "Akron", "Alabama", "Alabama A&M", "Alabama State",
    "Albany", "Albany State", "Albion", "Albright", "Alcorn State", "Alderson Broaddus", "Alfred", "Alfred State",
    "Allegheny", "Allen", "Alma", "Alvernia", "American International", "Amherst", "Anderson (IN)", "Anna Maria",
    "Appalachian State", "Apprentice", "Arizona", "Arizona Christian", "Arizona State", "Arkansas", "Arkansas Baptist",
    "Arkansas State", "Arkansas Tech", "Arkansas-Monticello", "Arkansas-Pine Bluff", "Army", "Asbury", "Ashland",
    "Assumption", "Auburn", "Augsburg", "Augustana (IL)", "Augustana (SD)", "Aurora", "Austin", "Austin Peay",
    "Ave Maria", "Averett", "Avila", "Azusa Pacific", "BYU", "Bacone", "Baker", "Baldwin Wallace", "Ball State",
    "Baptist Bible", "Bard", "Barton", "Bates", "Bay Path", "Bayamon Central", "Baylor", "Becker", "Belhaven",
    "Bemidji State", "Benedict", "Benedictine (IL)", "Benedictine (KS)", "Bentley", "Berry", "Bethany (KS)",
    "Bethany (WV)", "Bethel (KS)", "Bethel (MN)", "Bethel (TN)", "Bethune-Cookman", "Birmingham-Southern",
    "Black Hills State", "Blackburn", "Bloomsburg", "Bluefield", "Bluefield State", "Bluffton", "Boise State",
    "Boston College", "Bowdoin", "Bowie State", "Bowling Green", "Brevard", "Bridgewater (VA)", "Bridgewater State",
    "Brockport", "Brown", "Bryant", "Bucknell", "Buena Vista", "Buffalo", "Buffalo State", "Butler", "Cal Lutheran",
    "Cal Poly", "Cal Poly Humboldt", "California", "California (PA)", "Campbell", "Campbellsville", "Capital",
    "Carleton", "Carnegie Mellon", "Carroll (MT)", "Carroll (WI)", "Carson-Newman", "Carthage", "Case Western Reserve",
    "Castleton", "Catawba", "Catholic", "Cazenovia", "Centenary", "Central", "Central Arkansas", "Central Connecticut",
    "Central Methodist", "Central Michigan", "Central Missouri", "Central Oklahoma", "Central State",
    "Central Washington", "Centre", "Chadron State", "Chapman", "Charleston (WV)", "Charleston Southern", "Charlotte",
    "Chattanooga", "Chicago", "Chowan", "Christopher Newport", "Cincinnati", "Claremont-Mudd-Scripps", "Clarion",
    "Clark Atlanta", "Clarke", "Clemson", "Coast Guard", "Coastal Carolina", "Coe", "Colby", "Colgate",
    "College of Idaho", "Colorado", "Colorado College", "Colorado Mesa", "Colorado Mines", "Colorado State",
    "Colorado State-Pueblo", "Columbia", "Concord", "Concordia (MI)", "Concordia (MN)", "Concordia (NE)",
    "Concordia (WI)", "Concordia-Moorhead", "Concordia-St. Paul", "Connecticut", "Cornell", "Cornell College",
    "Cortland", "Cumberland", "Cumberlands", "Curry", "Dakota State", "Dakota Wesleyan", "Dartmouth", "Davenport",
    "Davidson", "Dayton", "Defiance", "Delaware", "Delaware State", "Delaware Valley", "Delta State", "Denison",
    "DePauw", "Dickinson", "Dickinson State", "Dixie State", "Doane", "Dodge City CC", "Dordt", "Drake", "Dubuque",
    "Duke", "Duquesne", "East Carolina", "East Central", "East Mississippi CC", "East Stroudsburg",
    "East Tennessee State", "East Texas A&M", "East Texas Baptist", "Eastern Illinois", "Eastern Kentucky",
    "Eastern Michigan", "Eastern New Mexico", "Eastern Oregon", "Eastern Washington", "Edward Waters",
    "Elizabeth City State", "Elmhurst", "Elon", "Emory & Henry", "Emporia State", "Endicott", "Erskine", "Eureka",
    "Evangel", "FDU-Florham", "Fairmont State", "Faulkner", "Fayetteville State", "Ferris State", "Ferrum",
    "Findlay", "Finlandia", "Fitchburg State", "Florida", "Florida A&M", "Florida Atlantic", "Florida International",
    "Florida Memorial", "Florida State", "Florida Tech", "Fordham", "Fort Hays State", "Fort Lewis", "Fort Scott CC",
    "Fort Valley State", "Framingham State", "Franklin", "Franklin & Marshall", "Franklin Pierce", "Fresno State",
    "Friends", "Frostburg State", "Furman", "Gallaudet", "Gannon", "Garden City CC", "Gardner-Webb", "Geneva",
    "George Fox", "Georgetown", "Georgetown (KY)", "Georgia", "Georgia Southern", "Georgia State", "Georgia Tech",
    "Gettysburg", "Glenville State", "Graceland", "Grambling State", "Grand Valley State", "Grand View", "Greensboro",
    "Greenville", "Grinnell", "Grove City", "Guilford", "Gustavus Adolphus", "Hamilton", "Hamline", "Hampden-Sydney",
    "Hampton", "Hanover", "Hardin-Simmons", "Harding", "Hartwick", "Harvard", "Hastings", "Haverford", "Hawaii",
    "Henderson State", "Hendrix", "Highland CC", "Hillsdale", "Hiram", "Hobart", "Hofstra", "Holy Cross", "Hope",
    "Houston", "Houston Christian", "Howard", "Howard Payne", "Humboldt State", "Huntingdon", "Husson", "Idaho",
    "Idaho State", "Illinois", "Illinois College", "Illinois State", "Illinois Wesleyan", "Incarnate Word",
    "Independence CC", "Indiana", "Indiana (PA)", "Indiana State", "Indiana Wesleyan", "Iowa", "Iowa Central CC",
    "Iowa State", "Iowa Western CC", "Ithaca", "Jackson State", "Jacksonville", "Jacksonville State", "James Madison",
    "John Carroll", "Johns Hopkins", "Johnson C. Smith", "Jones College", "Juniata", "Kalamazoo", "Kansas",
    "Kansas State", "Kansas Wesleyan", "Kean", "Keene State", "Kennesaw State", "Kent State", "Kentucky",
    "Kentucky Christian", "Kentucky State", "Kentucky Wesleyan", "Kenyon", "Keystone", "King's (PA)", "Knox",
    "Kutztown", "La Verne", "Lafayette", "Lake Erie", "Lake Forest", "Lakeland", "Lamar", "Lane", "Langston",
    "Lawrence", "Lebanon Valley", "Lehigh", "Lenoir-Rhyne", "Lewis & Clark", "Liberty", "Limestone", "Lincoln (CA)",
    "Lincoln (MO)", "Lincoln (PA)", "Lindenwood", "Lindsey Wilson", "Linfield", "Livingstone", "Long Island",
    "Louisiana", "Louisiana College", "Louisiana Tech", "Louisiana-Monroe", "Louisville", "LSU", "Lycoming", "Lyon",
    "Macalester", "MacMurray", "Maine", "Maine Maritime", "Malone", "Manchester", "Marian (IN)", "Marietta",
    "Marist", "Marshall", "Mary Hardin-Baylor", "Maryland", "Maryville", "Marywood", "Mass. Maritime",
    "Massachusetts", "Mayville State", "McDaniel", "McKendree", "McMurry", "McNeese", "McPherson", "Memphis", "Menlo",
    "Mercer", "Mercyhurst", "Merchant Marine", "Methodist", "Miami (FL)", "Miami (OH)", "Michigan", "Michigan State",
    "Michigan Tech", "Mid-America Christian", "Middle Tennessee", "Middlebury", "Midland", "Midwestern State",
    "Miles", "Millersville", "Milligan", "Millikin", "Millsaps", "Minnesota", "Minnesota State", "Minnesota-Crookston",
    "Minnesota-Duluth", "Minnesota-Morris", "Minot State", "Misericordia", "Mississippi College",
    "Mississippi Delta CC", "Mississippi Gulf Coast CC", "Mississippi State", "Mississippi Valley State", "Missouri",
    "Missouri Baptist", "Missouri S&T", "Missouri Southern", "Missouri State", "Missouri Valley", "Missouri Western",
    "MIT", "Monmouth", "Montana", "Montana State", "Montana State-Northern", "Montana Tech", "Montana Western",
    "Moravian", "Morehead State", "Morehouse", "Morgan State", "Morningside", "Morrisville State", "Mount Aloysius",
    "Mount Ida", "Mount Marty", "Mount Mercy", "Mount St. Joseph", "Mount Union", "Muhlenberg", "Murray State",
    "Muskingum", "Navy", "NC State", "Nebraska", "Nebraska Wesleyan", "Nebraska-Kearney", "Nevada",
    "New England College", "New Hampshire", "New Haven", "New Mexico", "New Mexico Highlands",
    "New Mexico Military Institute", "New Mexico State", "Newberry", "Nicholls", "Norfolk State", "North Alabama",
    "North Carolina", "North Carolina A&T", "North Carolina Central", "North Carolina Wesleyan", "North Central (IL)",
    "North Central (MN)", "North Dakota", "North Dakota State", "North Greenville", "North Park", "North Texas",
    "Northeast Mississippi CC", "Northeastern State", "Northern Arizona", "Northern Colorado", "Northern Illinois",
    "Northern Iowa", "Northern Michigan", "Northern State", "Northland", "Northwest Mississippi CC",
    "Northwest Missouri State", "Northwestern", "Northwestern (IA)", "Northwestern (MN)",
    "Northwestern Oklahoma State", "Northwestern State", "Northwood", "Norwich", "Notre Dame", "Notre Dame College",
    "Nova Southeastern", "Oberlin", "Occidental", "Oglethorpe", "Ohio", "Ohio Dominican", "Ohio Northern",
    "Ohio State", "Ohio Wesleyan", "Oklahoma", "Oklahoma Baptist", "Oklahoma Panhandle State", "Oklahoma State",
    "Old Dominion", "Ole Miss", "Olivet", "Olivet Nazarene", "Oregon", "Oregon State", "Ottawa", "Otterbein",
    "Ouachita Baptist", "Pace", "Pacific", "Pacific Lutheran", "Panhandle State", "Penn", "Penn State", "Peru State",
    "Pikeville", "Pittsburg State", "Pittsburgh", "Plymouth State", "Point", "Point (GA)", "Point University",
    "Pomona-Pitzer", "Post", "Prairie View A&M", "Presbyterian", "Presentation", "Princeton", "Principia", "Purdue",
    "Quincy", "Ramapo", "Randolph-Macon", "Redlands", "Reinhardt", "Rensselaer", "Rhode Island", "Rhodes", "Rice",
    "Richmond", "Ripon", "Robert Morris", "Rochester", "Rockford", "Rocky Mountain", "Roger Williams", "Rose-Hulman",
    "Rowan", "Rutgers", "Sacramento State", "Sacred Heart", "Saginaw Valley State", "Salisbury", "Salve Regina",
    "Sam Houston", "Samford", "San Diego", "San Diego State", "San Jose State", "Santa Clara", "Savannah State",
    "Schreiner", "Seton Hill", "Sewanee", "Shaw", "Shenandoah", "Shepherd", "Shippensburg", "Shorter", "Siena",
    "Simon Fraser", "Simpson", "Simpson (CA)", "Sioux Falls", "Slippery Rock", "SMU", "Snow College", "South Alabama",
    "South Carolina", "South Carolina State", "South Dakota", "South Dakota Mines", "South Dakota State",
    "South Florida", "Southeast Missouri State", "Southeastern", "Southeastern Louisiana",
    "Southeastern Oklahoma State", "Southern", "Southern Arkansas", "Southern Connecticut", "Southern Illinois",
    "Southern Nazarene", "Southern Oregon", "Southern Utah", "Southern Virginia", "Southwest Baptist",
    "Southwest Minnesota State", "Southwest Mississippi CC", "Southwestern", "Southwestern (KS)",
    "Southwestern Assemblies of God", "Southwestern Oklahoma State", "Springfield", "St. Ambrose", "St. Anselm",
    "St. Augustine's", "St. Cloud State", "St. Francis (IL)", "St. Francis (IN)", "St. Francis (PA)",
    "St. John Fisher", "St. John's (MN)", "St. Joseph's (IN)", "St. Lawrence", "St. Norbert", "St. Olaf",
    "St. Scholastica", "St. Thomas (MN)", "St. Vincent", "St. Xavier", "Stanford", "Stephen F. Austin", "Sterling",
    "Stetson", "Stevenson", "Stonehill", "Stony Brook", "Sul Ross State", "SUNY Maritime", "Susquehanna", "Syracuse",
    "Tabor", "Tarleton State", "TCU", "Temple", "Tennessee", "Tennessee State", "Tennessee Tech", "Tennessee Wesleyan",
    "Texas", "Texas A&M", "Texas A&M-Commerce", "Texas A&M-Kingsville", "Texas College", "Texas Lutheran",
    "Texas Southern", "Texas State", "Texas Tech", "Texas Wesleyan", "The Citadel", "Thiel", "Thomas More", "Tiffin",
    "Toledo", "Towson", "Trine", "Trinity (CT)", "Trinity (TX)", "Trinity International", "Troy", "Truman State",
    "Tufts", "Tulane", "Tulsa", "Tusculum", "Tuskegee", "UAB", "UAlbany", "UC Davis", "UCF", "UCLA", "UConn",
    "UMass Dartmouth", "Union (KY)", "Union (NY)", "UNLV", "Upper Iowa", "Ursinus", "USC", "UT Martin",
    "UT Permian Basin", "Utah", "Utah State", "Utah Tech", "UTEP", "UTSA", "Valdosta State", "Valley City State",
    "Valparaiso", "Vanderbilt", "Virginia", "Virginia Lynchburg", "Virginia State", "Virginia Tech", "Virginia Union",
    "Virginia-Wise", "VMI", "Wabash", "Wagner", "Wake Forest", "Waldorf", "Walsh", "Warner", "Warner Pacific",
    "Wartburg", "Washburn", "Washington", "Washington & Jefferson", "Washington & Lee", "Washington State",
    "Washington University", "Wayne State (MI)", "Wayne State (NE)", "Waynesburg", "Weber State", "Webber International",
    "Wesley", "Wesleyan", "West Alabama", "West Chester", "West Florida", "West Georgia", "West Liberty",
    "West Texas A&M", "West Virginia", "West Virginia State", "West Virginia Wesleyan", "Western Carolina",
    "Western Colorado", "Western Connecticut", "Western Illinois", "Western Kentucky", "Western Michigan",
    "Western New England", "Western New Mexico", "Western Oregon", "Western State", "Western Washington",
    "Westfield State", "Westminster (MO)", "Westminster (PA)", "Wheaton (IL)", "Wheaton (MA)", "Wheeling", "Whittier",
    "Whitworth", "Widener", "Wilkes", "Willamette", "William & Mary", "William Jewell", "William Paterson",
    "William Penn", "Williams", "Wilmington", "Wingate", "Winona State", "Winston-Salem State", "Wisconsin",
    "Wisconsin Lutheran", "Wisconsin-Eau Claire", "Wisconsin-La Crosse", "Wisconsin-Oshkosh", "Wisconsin-Platteville",
    "Wisconsin-River Falls", "Wisconsin-Stevens Point", "Wisconsin-Stout", "Wisconsin-Whitewater", "Wittenberg",
    "Wofford", "Wooster", "Worcester State", "Wyoming", "Yale", "York (NE)", "Youngstown State",
]

COLLEGES_BY_STATE = [
    ("Abilene Christian", "TX", "FCS"),
    ("Adams State", "CO", "D2"),
    ("Adrian", "MI", "D3"),
    ("Akron", "OH", "FBS"),
    ("Alabama", "AL", "FBS"),
    ("Alabama A&M", "AL", "FCS"),
    ("Alabama State", "AL", "FCS"),
    ("Albany", "NY", "FCS"),
    ("Albany State University (Georgia)", "GA", "D2"),
    ("Albion", "MI", "D3"),
    ("Albright", "PA", "D3"),
    ("Alcorn State", "MS", "FCS"),
    ("Alfred", "NY", "D3"),
    ("Alfred State", "NY", "D3"),
    ("Allegheny", "PA", "D3"),
    ("Allen", "SC", "D2"),
    ("Alma", "MI", "D3"),
    ("Alvernia", "PA", "D3"),
    ("American International", "MA", "D2"),
    ("Amherst", "MA", "D3"),
    ("Anderson University (Indiana)", "IN", "D3"),
    ("Anderson University (South Carolina)", "SC", "D2"),
    ("Angelo State", "TX", "D2"),
    ("Anna Maria", "MA", "D3"),
    ("Appalachian State", "NC", "FBS"),
    ("Arizona", "AZ", "FBS"),
    ("Arizona State", "AZ", "FBS"),
    ("Arkansas", "AR", "D2"),
    ("Arkansas", "AR", "FBS"),
    ("Arkansas State", "AR", "FBS"),
    ("Arkansas Tech", "AR", "D2"),
    ("Arkansas-Pine Bluff", "AR", "FCS"),
    ("Ashland", "OH", "D2"),
    ("Assumption", "MA", "D2"),
    ("Auburn", "AL", "FBS"),
    ("Augsburg", "MN", "D3"),
    ("Augustana College (Illinois)", "IL", "D3"),
    ("Augustana University (South Dakota)", "SD", "D2"),
    ("Aurora", "IL", "D3"),
    ("Austin", "TX", "D3"),
    ("Austin Peay State", "TN", "FCS"),
    ("Averett", "VA", "D3"),
    ("BYU", "UT", "FBS"),
    ("Baldwin Wallace", "OH", "D3"),
    ("Ball State", "IN", "FBS"),
    ("Barton", "NC", "D2"),
    ("Bates", "ME", "D3"),
    ("Baylor", "TX", "FBS"),
    ("Belhaven", "MS", "D3"),
    ("Beloit", "WI", "D3"),
    ("Bemidji State", "MN", "D2"),
    ("Benedict", "SC", "D2"),
    ("Benedictine University (Illinois)", "IL", "D3"),
    ("Bentley", "MA", "D2"),
    ("Berry", "GA", "D3"),
    ("Bethany College (West Virginia)", "WV", "D3"),
    ("Bethel University (Minnesota)", "MN", "D3"),
    ("Bethune-Cookman", "FL", "FCS"),
    ("Black Hills State", "SD", "D2"),
    ("Bloomsburg University of Pennsylvania", "PA", "D2"),
    ("Bluefield State", "WV", "D2"),
    ("Bluffton", "OH", "D3"),
    ("Boise State", "ID", "FBS"),
    ("Boston", "MA", "FBS"),
    ("Bowdoin", "ME", "D3"),
    ("Bowie State", "MD", "D2"),
    ("Bowling Green State", "OH", "FBS"),
    ("Brevard", "NC", "D3"),
    ("Bridgewater College (Virginia)", "VA", "D3"),
    ("Bridgewater State", "MA", "D3"),
    ("Brown", "RI", "FCS"),
    ("Bryant", "RI", "FCS"),
    ("Bucknell", "PA", "FCS"),
    ("Buena Vista", "IA", "D3"),
    ("Buffalo State", "NY", "D3"),
    ("Butler", "IN", "FCS"),
    ("California", "CA", "FBS"),
    ("California Lutheran", "CA", "D3"),
    ("California Polytechnic State", "CA", "FCS"),
    ("California State University", "CA", "FBS"),
    ("California State University", "CA", "FCS"),
    ("Calvin", "MI", "D3"),
    ("Campbell", "NC", "FCS"),
    ("Capital", "OH", "D3"),
    ("Carleton", "MN", "D3"),
    ("Carnegie Mellon", "PA", "D3"),
    ("Carroll University (Wisconsin)", "WI", "D3"),
    ("Carson-Newman", "TN", "D2"),
    ("Carthage", "WI", "D3"),
    ("Case Western Reserve", "OH", "D3"),
    ("Catawba", "NC", "D2"),
    ("Catholic", "DC", "D3"),
    ("Centenary College (Louisiana)", "LA", "D3"),
    ("Central Arkansas", "AR", "FCS"),
    ("Central College (Iowa)", "IA", "D3"),
    ("Central Connecticut State", "CT", "FCS"),
    ("Central Michigan", "MI", "FBS"),
    ("Central Missouri", "MO", "D2"),
    ("Central Oklahoma", "OK", "D2"),
    ("Central State", "OH", "D2"),
    ("Central Washington", "WA", "D2"),
    ("Centre", "KY", "D3"),
    ("Chadron State", "NE", "D2"),
    ("Chapman", "CA", "D3"),
    ("Charleston (West Virginia)", "WV", "D2"),
    ("Charleston Southern", "SC", "FCS"),
    ("Chattanooga", "TN", "FCS"),
    ("Chicago", "IL", "D3"),
    ("Chowan", "NC", "D2"),
    ("Christopher Newport", "VA", "D3"),
    ("Cincinnati", "OH", "FBS"),
    ("Claremont McKenna-Harvey Mudd-Scripps Colleges", "CA", "D3"),
    ("Clark Atlanta", "GA", "D2"),
    ("Clemson", "SC", "FBS"),
    ("Coastal Carolina", "SC", "FBS"),
    ("Coe", "IA", "D3"),
    ("Colby", "ME", "D3"),
    ("Colgate", "NY", "FCS"),
    ("College of the Holy Cross", "MA", "FCS"),
    ("Colorado Boulder", "CO", "FBS"),
    ("Colorado Mesa", "CO", "D2"),
    ("Colorado School of Mines", "CO", "D2"),
    ("Colorado State", "CO", "FBS"),
    ("Colorado State University Pueblo", "CO", "D2"),
    ("Columbia University-Barnard", "NY", "FCS"),
    ("Concord", "WV", "D2"),
    ("Concordia College", "MN", "D3"),
    ("Concordia University", "MN", "D2"),
    ("Concordia University Chicago", "IL", "D3"),
    ("Concordia University Wisconsin", "WI", "D3"),
    ("Cornell", "IA", "D3"),
    ("Cornell", "NY", "FCS"),
    ("Crown College (Minnesota)", "MN", "D3"),
    ("Curry", "MA", "D3"),
    ("Dartmouth", "NH", "FCS"),
    ("Davenport", "MI", "D2"),
    ("Davidson", "NC", "FCS"),
    ("Dayton", "OH", "FCS"),
    ("DePauw", "IN", "D3"),
    ("Dean", "MA", "D3"),
    ("Delaware", "DE", "FBS"),
    ("Delaware State", "DE", "FCS"),
    ("Delaware Valley", "PA", "D3"),
    ("Delta State", "MS", "D2"),
    ("Denison", "OH", "D3"),
    ("Dickinson", "PA", "D3"),
    ("Drake", "IA", "FCS"),
    ("Dubuque", "IA", "D3"),
    ("Duke", "NC", "FBS"),
    ("Duquesne", "PA", "FCS"),
    ("East Carolina", "NC", "FBS"),
    ("East Central", "OK", "D2"),
    ("East Stroudsburg University of Pennsylvania", "PA", "D2"),
    ("East Tennessee State", "TN", "FCS"),
    ("East Texas A&M", "TX", "FCS"),
    ("East Texas Baptist", "TX", "D3"),
    ("Eastern", "PA", "D3"),
    ("Eastern Illinois", "IL", "FCS"),
    ("Eastern Kentucky", "KY", "FCS"),
    ("Eastern Michigan", "MI", "FBS"),
    ("Eastern New Mexico", "NM", "D2"),
    ("Eastern Washington", "WA", "FCS"),
    ("Edward Waters", "FL", "D2"),
    ("Elizabeth City State", "NC", "D2"),
    ("Elmhurst", "IL", "D3"),
    ("Elon", "NC", "FCS"),
    ("Emory & Henry", "VA", "D2"),
    ("Emporia State", "KS", "D2"),
    ("Endicott", "MA", "D3"),
    ("Erskine", "SC", "D2"),
    ("Eureka", "IL", "D3"),
    ("FIU", "FL", "FBS"),
    ("Fairleigh Dickinson University", "NJ", "D3"),
    ("Fairmont State", "WV", "D2"),
    ("Fayetteville State", "NC", "D2"),
    ("Ferris State", "MI", "D2"),
    ("Ferrum", "VA", "D2"),
    ("Findlay", "OH", "D2"),
    ("Fitchburg State", "MA", "D3"),
    ("Florida", "FL", "FBS"),
    ("Florida A&M", "FL", "FCS"),
    ("Florida Atlantic", "FL", "FBS"),
    ("Florida State", "FL", "FBS"),
    ("Fordham", "NY", "FCS"),
    ("Fort Hays State", "KS", "D2"),
    ("Fort Lewis", "CO", "D2"),
    ("Fort Valley State", "GA", "D2"),
    ("Framingham State", "MA", "D3"),
    ("Franklin", "IN", "D3"),
    ("Franklin & Marshall", "PA", "D3"),
    ("Franklin Pierce", "NH", "D2"),
    ("Frostburg State", "MD", "D2"),
    ("Furman", "SC", "FCS"),
    ("Gallaudet", "DC", "D3"),
    ("Gannon", "PA", "D2"),
    ("Gardner-Webb", "NC", "FCS"),
    ("Geneva", "PA", "D3"),
    ("George Fox", "OR", "D3"),
    ("Georgetown", "DC", "FCS"),
    ("Georgia", "GA", "FBS"),
    ("Georgia Southern", "GA", "FBS"),
    ("Georgia State", "GA", "FBS"),
    ("Gettysburg", "PA", "D3"),
    ("Glenville State", "WV", "D2"),
    ("Grambling State", "LA", "FCS"),
    ("Grand Valley State", "MI", "D2"),
    ("Greensboro", "NC", "D3"),
    ("Greenville", "IL", "D3"),
    ("Grinnell", "IA", "D3"),
    ("Grove City", "PA", "D3"),
    ("Guilford", "NC", "D3"),
    ("Gustavus Adolphus", "MN", "D3"),
    ("Hamilton", "NY", "D3"),
    ("Hamline", "MN", "D3"),
    ("Hampden-Sydney", "VA", "D3"),
    ("Hampton", "VA", "FCS"),
    ("Hanover", "IN", "D3"),
    ("Hardin-Simmons", "TX", "D3"),
    ("Harding", "AR", "D2"),
    ("Hartwick", "NY", "D3"),
    ("Harvard", "MA", "FCS"),
    ("Hawaii", "HI", "FBS"),
    ("Heidelberg", "OH", "D3"),
    ("Henderson State", "AR", "D2"),
    ("Hendrix", "AR", "D3"),
    ("Hilbert", "NY", "D3"),
    ("Hillsdale", "MI", "D2"),
    ("Hiram", "OH", "D3"),
    ("Hobart and William Smith Colleges", "NY", "D3"),
    ("Hope", "MI", "D3"),
    ("Houston", "TX", "FBS"),
    ("Houston Christian", "TX", "FCS"),
    ("Howard", "DC", "FCS"),
    ("Howard Payne", "TX", "D3"),
    ("Huntingdon", "AL", "D3"),
    ("Husson", "ME", "D3"),
    ("Idaho", "ID", "FCS"),
    ("Idaho State", "ID", "FCS"),
    ("Illinois", "IL", "D3"),
    ("Illinois State", "IL", "FCS"),
    ("Illinois Urbana-Champaign", "IL", "FBS"),
    ("Illinois Wesleyan", "IL", "D3"),
    ("Indiana State", "IN", "FCS"),
    ("Indiana University", "IN", "FBS"),
    ("Indiana University of Pennsylvania", "PA", "D2"),
    ("Indianapolis", "IN", "D2"),
    ("Iowa", "IA", "FBS"),
    ("Iowa State", "IA", "FBS"),
    ("Ithaca", "NY", "D3"),
    ("Jackson State", "MS", "FCS"),
    ("Jacksonville State", "AL", "FBS"),
    ("James Madison", "VA", "FBS"),
    ("Jamestown", "ND", "D2"),
    ("John Carroll", "OH", "D3"),
    ("Johns Hopkins", "MD", "D3"),
    ("Johnson C. Smith", "NC", "D2"),
    ("Juniata", "PA", "D3"),
    ("Kalamazoo", "MI", "D3"),
    ("Kansas", "KS", "FBS"),
    ("Kansas State", "KS", "FBS"),
    ("Kean", "NJ", "D3"),
    ("Kennesaw State", "GA", "FBS"),
    ("Kent State", "OH", "FBS"),
    ("Kentucky", "KY", "FBS"),
    ("Kentucky State", "KY", "D2"),
    ("Kentucky Wesleyan", "KY", "D2"),
    ("Kenyon", "OH", "D3"),
    ("King's College (Pennsylvania)", "PA", "D3"),
    ("Knox", "IL", "D3"),
    ("Kutztown University of Pennsylvania", "PA", "D2"),
    ("LSU", "LA", "FBS"),
    ("La Verne", "CA", "D3"),
    ("LaGrange", "GA", "D3"),
    ("Lafayette", "PA", "FCS"),
    ("Lake Erie", "OH", "D2"),
    ("Lake Forest", "IL", "D3"),
    ("Lakeland", "WI", "D3"),
    ("Lamar", "TX", "FCS"),
    ("Lane", "TN", "D2"),
    ("Lawrence", "WI", "D3"),
    ("Lebanon Valley", "PA", "D3"),
    ("Lehigh", "PA", "FCS"),
    ("Lenoir-Rhyne", "NC", "D2"),
    ("Lewis & Clark", "OR", "D3"),
    ("Liberty", "VA", "FBS"),
    ("Lincoln University (Missouri)", "MO", "D2"),
    ("Lincoln University (Pennsylvania)", "PA", "D2"),
    ("Lindenwood", "MO", "FCS"),
    ("Linfield", "OR", "D3"),
    ("Livingstone", "NC", "D2"),
    ("Lock Haven University of Pennsylvania", "PA", "D2"),
    ("Long Island", "NY", "FCS"),
    ("Loras", "IA", "D3"),
    ("Louisiana Monroe", "LA", "FBS"),
    ("Louisiana Tech", "LA", "FBS"),
    ("Louisiana at Lafayette", "LA", "FBS"),
    ("Louisville", "KY", "FBS"),
    ("Luther", "IA", "D3"),
    ("Lycoming", "PA", "D3"),
    ("Lyon", "AR", "D3"),
    ("Macalester", "MN", "D3"),
    ("Maine", "ME", "FCS"),
    ("Maine Maritime Academy", "ME", "D3"),
    ("Manchester", "IN", "D3"),
    ("Marietta", "OH", "D3"),
    ("Marist", "NY", "FCS"),
    ("Mars Hill", "NC", "D2"),
    ("Marshall", "WV", "FBS"),
    ("Martin Luther", "MN", "D3"),
    ("Mary", "ND", "D2"),
    ("Mary Hardin-Baylor", "TX", "D3"),
    ("Maryland", "MD", "FBS"),
    ("Maryville College (Tennessee)", "TN", "D3"),
    ("Massachusetts", "MA", "D3"),
    ("Massachusetts Maritime Academy", "MA", "D3"),
    ("McDaniel", "MD", "D3"),
    ("McKendree", "IL", "D2"),
    ("McMurry", "TX", "D3"),
    ("McNeese State", "LA", "FCS"),
    ("Memphis", "TN", "FBS"),
    ("Mercer", "GA", "FCS"),
    ("Mercyhurst", "PA", "FCS"),
    ("Merrimack", "MA", "FCS"),
    ("Methodist", "NC", "D3"),
    ("Miami (FL)", "FL", "FBS"),
    ("Miami University (Ohio)", "OH", "FBS"),
    ("Michigan", "MI", "FBS"),
    ("Michigan State", "MI", "FBS"),
    ("Michigan Technological", "MI", "D2"),
    ("Middle Tennessee State", "TN", "FBS"),
    ("Middlebury", "VT", "D3"),
    ("Midwestern State", "TX", "D2"),
    ("Miles", "AL", "D2"),
    ("Millersville University of Pennsylvania", "PA", "D2"),
    ("Millikin", "IL", "D3"),
    ("Millsaps", "MS", "D3"),
    ("Minnesota", "MN", "FBS"),
    ("Minnesota Duluth", "MN", "D2"),
    ("Minnesota State University", "MN", "D2"),
    ("Minnesota State University Moorhead", "MN", "D2"),
    ("Minnesota-Morris", "MN", "D3"),
    ("Minot State", "ND", "D2"),
    ("Misericordia", "PA", "D3"),
    ("Mississippi State", "MS", "FBS"),
    ("Mississippi Valley State", "MS", "FCS"),
    ("Missouri", "MO", "FBS"),
    ("Missouri Southern State", "MO", "D2"),
    ("Missouri State", "MO", "FBS"),
    ("Missouri University of Science and Technology", "MO", "D2"),
    ("Missouri Western State", "MO", "D2"),
    ("Monmouth", "NJ", "FCS"),
    ("Monmouth College (Illinois)", "IL", "D3"),
    ("Montana", "MT", "FCS"),
    ("Montana State University-Bozeman", "MT", "FCS"),
    ("Montclair State", "NJ", "D3"),
    ("Moravian", "PA", "D3"),
    ("Morehead State", "KY", "FCS"),
    ("Morehouse", "GA", "D2"),
    ("Morgan State", "MD", "FCS"),
    ("Mount St. Joseph", "OH", "D3"),
    ("Mount Union", "OH", "D3"),
    ("Muhlenberg", "PA", "D3"),
    ("Murray State", "KY", "FCS"),
    ("Muskingum", "OH", "D3"),
    ("Nebraska", "NE", "FBS"),
    ("Nebraska Wesleyan", "NE", "D3"),
    ("Nebraska at Kearney", "NE", "D2"),
    ("Nevada", "NV", "FBS"),
    ("New England", "ME", "D3"),
    ("New England", "NH", "D3"),
    ("New Hampshire", "NH", "FCS"),
    ("New Haven", "CT", "FCS"),
    ("New Mexico", "NM", "FBS"),
    ("New Mexico Highlands", "NM", "D2"),
    ("New Mexico State", "NM", "FBS"),
    ("Newberry", "SC", "D2"),
    ("Nicholls State", "LA", "FCS"),
    ("Nichols", "MA", "D3"),
    ("Norfolk State", "VA", "FCS"),
    ("North Alabama", "AL", "FCS"),
    ("North Carolina", "NC", "FBS"),
    ("North Carolina A&T State", "NC", "FCS"),
    ("North Carolina Central", "NC", "FCS"),
    ("North Carolina State", "NC", "FBS"),
    ("North Carolina Wesleyan", "NC", "D3"),
    ("North Carolina at Charlotte", "NC", "FBS"),
    ("North Carolina at Pembroke", "NC", "D2"),
    ("North Central", "IL", "D3"),
    ("North Dakota", "ND", "FCS"),
    ("North Dakota State", "ND", "FCS"),
    ("North Greenville", "SC", "D2"),
    ("North Park", "IL", "D3"),
    ("North Texas", "TX", "FBS"),
    ("Northeastern State", "OK", "D2"),
    ("Northern Arizona", "AZ", "FCS"),
    ("Northern Colorado", "CO", "FCS"),
    ("Northern Illinois", "IL", "FBS"),
    ("Northern Iowa", "IA", "FCS"),
    ("Northern Michigan", "MI", "D2"),
    ("Northern State", "SD", "D2"),
    ("Northwest Missouri State", "MO", "D2"),
    ("Northwestern", "IL", "FBS"),
    ("Northwestern Oklahoma State", "OK", "D2"),
    ("Northwestern State", "LA", "FCS"),
    ("Northwestern-St. Paul", "MN", "D3"),
    ("Northwood", "MI", "D2"),
    ("Norwich", "VT", "D3"),
    ("Notre Dame", "IN", "FBS"),
    ("Oberlin", "OH", "D3"),
    ("Ohio", "OH", "FBS"),
    ("Ohio Dominican", "OH", "D2"),
    ("Ohio Northern", "OH", "D3"),
    ("Ohio Wesleyan", "OH", "D3"),
    ("Oklahoma", "OK", "FBS"),
    ("Oklahoma Baptist", "OK", "D2"),
    ("Oklahoma State", "OK", "FBS"),
    ("Old Dominion", "VA", "FBS"),
    ("Ole Miss", "MS", "FBS"),
    ("Olivet", "MI", "D3"),
    ("Oregon", "OR", "FBS"),
    ("Oregon State", "OR", "FBS"),
    ("Otterbein", "OH", "D3"),
    ("Ouachita Baptist", "AR", "D2"),
    ("Pace", "NY", "D2"),
    ("Pacific Lutheran", "WA", "D3"),
    ("Pacific University (Oregon)", "OR", "D3"),
    ("Penn", "PA", "FCS"),
    ("Pennsylvania State", "PA", "FBS"),
    ("Pennsylvania Western University", "PA", "D2"),
    ("Pittsburg State", "KS", "D2"),
    ("Pittsburgh", "PA", "FBS"),
    ("Plymouth State", "NH", "D3"),
    ("Pomona-Pitzer Colleges", "CA", "D3"),
    ("Portland State", "OR", "FCS"),
    ("Post", "CT", "D2"),
    ("Prairie View A&M", "TX", "FCS"),
    ("Presbyterian", "SC", "FCS"),
    ("Princeton", "NJ", "FCS"),
    ("Puget Sound", "WA", "D3"),
    ("Purdue", "IN", "FBS"),
    ("Quincy", "IL", "D2"),
    ("Randolph-Macon", "VA", "D3"),
    ("Redlands", "CA", "D3"),
    ("Rensselaer Polytechnic", "NY", "D3"),
    ("Rhode Island", "RI", "FCS"),
    ("Rhodes", "TN", "D3"),
    ("Rice", "TX", "FBS"),
    ("Richmond", "VA", "FCS"),
    ("Ripon", "WI", "D3"),
    ("Roanoke", "VA", "D3"),
    ("Robert Morris", "PA", "FCS"),
    ("Rochester", "NY", "D3"),
    ("Rockford", "IL", "D3"),
    ("Roosevelt", "IL", "D2"),
    ("Rose-Hulman", "IN", "D3"),
    ("Rowan", "NJ", "D3"),
    ("Rutgers", "NJ", "FBS"),
    ("SMU", "TX", "FBS"),
    ("Sacred Heart", "CT", "FCS"),
    ("Saginaw Valley State", "MI", "D2"),
    ("Saint Anselm", "NH", "D2"),
    ("Saint Francis", "PA", "FCS"),
    ("Saint John's University (Minnesota)", "MN", "D3"),
    ("Saint Vincent", "PA", "D3"),
    ("Salisbury", "MD", "D3"),
    ("Salve Regina", "RI", "D3"),
    ("Sam Houston State", "TX", "FBS"),
    ("Samford", "AL", "FCS"),
    ("San Diego", "CA", "FCS"),
    ("San Diego State", "CA", "FBS"),
    ("San Jose State", "CA", "FBS"),
    ("Savannah State", "GA", "D2"),
    ("Seton Hill", "PA", "D2"),
    ("Shaw", "NC", "D2"),
    ("Shenandoah", "VA", "D3"),
    ("Shepherd", "WV", "D2"),
    ("Shippensburg University of Pennsylvania", "PA", "D2"),
    ("Shorter", "GA", "D2"),
    ("Simpson", "IA", "D3"),
    ("Sioux Falls", "SD", "D2"),
    ("Slippery Rock University of Pennsylvania", "PA", "D2"),
    ("South Alabama", "AL", "FBS"),
    ("South Carolina", "SC", "FBS"),
    ("South Carolina State", "SC", "FCS"),
    ("South Dakota", "SD", "FCS"),
    ("South Dakota School of Mines & Technology", "SD", "D2"),
    ("South Dakota State", "SD", "FCS"),
    ("South Florida", "FL", "FBS"),
    ("Southeast Missouri State", "MO", "FCS"),
    ("Southeastern Louisiana", "LA", "FCS"),
    ("Southeastern Oklahoma State", "OK", "D2"),
    ("Southern Arkansas", "AR", "D2"),
    ("Southern Connecticut State", "CT", "D2"),
    ("Southern Illinois University at Carbondale", "IL", "FCS"),
    ("Southern Miss", "MS", "FBS"),
    ("Southern Nazarene", "OK", "D2"),
    ("Southern University", "LA", "FCS"),
    ("Southern Utah", "UT", "FCS"),
    ("Southern Virginia", "VA", "D3"),
    ("Southwest Baptist", "MO", "D2"),
    ("Southwest Minnesota State", "MN", "D2"),
    ("Southwestern Oklahoma State", "OK", "D2"),
    ("Springfield", "MA", "D3"),
    ("St. John Fisher", "NY", "D3"),
    ("St. Lawrence", "NY", "D3"),
    ("St. Norbert", "WI", "D3"),
    ("St. Olaf", "MN", "D3"),
    ("St. Thomas (Minnesota)", "MN", "FCS"),
    ("Stanford", "CA", "FBS"),
    ("State University of New York Maritime", "NY", "D3"),
    ("State University of New York at Brockport", "NY", "D3"),
    ("State University of New York at Cortland", "NY", "D3"),
    ("State University of New York at Morrisville", "NY", "D3"),
    ("Stephen F. Austin State", "TX", "FCS"),
    ("Stetson", "FL", "FCS"),
    ("Stevenson", "MD", "D3"),
    ("Stonehill", "MA", "FCS"),
    ("Stony Brook", "NY", "FCS"),
    ("Sul Ross State", "TX", "D2"),
    ("Susquehanna", "PA", "D3"),
    ("Syracuse", "NY", "FBS"),
    ("TCU", "TX", "FBS"),
    ("Tarleton State", "TX", "FCS"),
    ("Temple", "PA", "FBS"),
    ("Tennessee", "TN", "FBS"),
    ("Tennessee State", "TN", "FCS"),
    ("Tennessee Technological", "TN", "FCS"),
    ("Texas", "TX", "FBS"),
    ("Texas A&M University", "TX", "FBS"),
    ("Texas A&M-Kingsville", "TX", "D2"),
    ("Texas Lutheran", "TX", "D3"),
    ("Texas Permian Basin", "TX", "D2"),
    ("Texas Southern", "TX", "FCS"),
    ("Texas State", "TX", "FBS"),
    ("Texas Tech", "TX", "FBS"),
    ("The Citadel", "SC", "FCS"),
    ("The College of New Jersey", "NJ", "D3"),
    ("The College of St. Scholastica", "MN", "D3"),
    ("The College of Wooster", "OH", "D3"),
    ("The Ohio State", "OH", "FBS"),
    ("Thiel", "PA", "D3"),
    ("Thomas More", "KY", "D2"),
    ("Tiffin", "OH", "D2"),
    ("Toledo", "OH", "FBS"),
    ("Towson", "MD", "FCS"),
    ("Trine", "IN", "D3"),
    ("Trinity College (Connecticut)", "CT", "D3"),
    ("Trinity University (Texas)", "TX", "D3"),
    ("Troy", "AL", "FBS"),
    ("Truman State", "MO", "D2"),
    ("Tufts", "MA", "D3"),
    ("Tulane", "LA", "FBS"),
    ("Tulsa", "OK", "FBS"),
    ("Tusculum", "TN", "D2"),
    ("Tuskegee", "AL", "D2"),
    ("U.S. Air Force Academy", "CO", "FBS"),
    ("U.S. Coast Guard Academy", "CT", "D3"),
    ("U.S. Merchant Marine Academy", "NY", "D3"),
    ("U.S. Military Academy", "NY", "FBS"),
    ("U.S. Naval Academy", "MD", "FBS"),
    ("UAB", "AL", "FBS"),
    ("UC Davis", "CA", "FCS"),
    ("UCF", "FL", "FBS"),
    ("UCLA", "CA", "FBS"),
    ("UConn", "CT", "FBS"),
    ("UMass", "MA", "FBS"),
    ("UNLV", "NV", "FBS"),
    ("USC", "CA", "FBS"),
    ("UT Martin", "TN", "FCS"),
    ("UTEP", "TX", "FBS"),
    ("UTRGV", "TX", "FCS"),
    ("UTSA", "TX", "FBS"),
    ("UVA Wise", "VA", "D2"),
    ("Union College (New York)", "NY", "D3"),
    ("University at Buffalo", "NY", "FBS"),
    ("Upper Iowa", "IA", "D2"),
    ("Ursinus", "PA", "D3"),
    ("Utah", "UT", "FBS"),
    ("Utah State", "UT", "FBS"),
    ("Utah Tech", "UT", "FCS"),
    ("Utica", "NY", "D3"),
    ("Valdosta State", "GA", "D2"),
    ("Valparaiso", "IN", "FCS"),
    ("Vanderbilt", "TN", "FBS"),
    ("Vermont State University Castleton", "VT", "D3"),
    ("Villanova", "PA", "FCS"),
    ("Virginia", "VA", "FBS"),
    ("Virginia Military", "VA", "FCS"),
    ("Virginia State", "VA", "D2"),
    ("Virginia Tech", "VA", "FBS"),
    ("Virginia Union", "VA", "D2"),
    ("Wabash", "IN", "D3"),
    ("Wagner", "NY", "FCS"),
    ("Wake Forest", "NC", "FBS"),
    ("Walsh", "OH", "D2"),
    ("Wartburg", "IA", "D3"),
    ("Washburn", "KS", "D2"),
    ("Washington", "WA", "FBS"),
    ("Washington State", "WA", "FBS"),
    ("Washington University in St. Louis", "MO", "D3"),
    ("Washington and Jefferson", "PA", "D3"),
    ("Washington and Lee", "VA", "D3"),
    ("Wayne State College (Nebraska)", "NE", "D2"),
    ("Wayne State University (Michigan)", "MI", "D2"),
    ("Waynesburg", "PA", "D3"),
    ("Weber State", "UT", "FCS"),
    ("Wesleyan University (Connecticut)", "CT", "D3"),
    ("West Alabama", "AL", "D2"),
    ("West Chester University of Pennsylvania", "PA", "D2"),
    ("West Florida", "FL", "D2"),
    ("West Georgia", "GA", "FCS"),
    ("West Liberty", "WV", "D2"),
    ("West Texas A&M", "TX", "D2"),
    ("West Virginia", "WV", "FBS"),
    ("West Virginia State", "WV", "D2"),
    ("West Virginia Wesleyan", "WV", "D2"),
    ("Western Carolina", "NC", "FCS"),
    ("Western Colorado", "CO", "D2"),
    ("Western Connecticut State", "CT", "D3"),
    ("Western Illinois", "IL", "FCS"),
    ("Western Kentucky", "KY", "FBS"),
    ("Western Michigan", "MI", "FBS"),
    ("Western New England", "MA", "D3"),
    ("Western New Mexico", "NM", "D2"),
    ("Western Oregon", "OR", "D2"),
    ("Westfield State", "MA", "D3"),
    ("Westminster College (Missouri)", "MO", "D3"),
    ("Westminster College (Pennsylvania)", "PA", "D3"),
    ("Wheaton College (Illinois)", "IL", "D3"),
    ("Wheeling", "WV", "D2"),
    ("Whitworth", "WA", "D3"),
    ("Widener", "PA", "D3"),
    ("Wilkes", "PA", "D3"),
    ("Willamette", "OR", "D3"),
    ("William & Mary", "VA", "FCS"),
    ("William Jewell", "MO", "D2"),
    ("William Paterson University of New Jersey", "NJ", "D3"),
    ("Williams", "MA", "D3"),
    ("Wilmington College (Ohio)", "OH", "D3"),
    ("Wingate", "NC", "D2"),
    ("Winona State", "MN", "D2"),
    ("Winston-Salem State", "NC", "D2"),
    ("Wisconsin", "WI", "FBS"),
    ("Wisconsin Lutheran", "WI", "D3"),
    ("Wisconsin-Eau Claire", "WI", "D3"),
    ("Wisconsin-La Crosse", "WI", "D3"),
    ("Wisconsin-Oshkosh", "WI", "D3"),
    ("Wisconsin-Platteville", "WI", "D3"),
    ("Wisconsin-River Falls", "WI", "D3"),
    ("Wisconsin-Stevens Point", "WI", "D3"),
    ("Wisconsin-Stout", "WI", "D3"),
    ("Wisconsin-Whitewater", "WI", "D3"),
    ("Wittenberg", "OH", "D3"),
    ("Wofford", "SC", "FCS"),
    ("Worcester Polytechnic", "MA", "D3"),
    ("Worcester State", "MA", "D3"),
    ("Wyoming", "WY", "FBS"),
    ("Yale", "CT", "FCS"),
    ("Youngstown State", "OH", "FCS"),
    ("the Incarnate Word", "TX", "FCS"),
    ("the South", "TN", "D3"),
    ("Arizona Christian", "AZ", "NAIA"),
    ("Arkansas Baptist", "AR", "NAIA"),
    ("Ave Maria", "FL", "NAIA"),
    ("Avila", "MO", "NAIA"),
    ("Baker", "KS", "NAIA"),
    ("Benedictine (KS)", "KS", "NAIA"),
    ("Bethany (KS)", "KS", "NAIA"),
    ("Bethel (KS)", "KS", "NAIA"),
    ("Bethel (TN)", "TN", "NAIA"),
    ("Bluefield", "VA", "NAIA"),
    ("Briar Cliff", "IA", "NAIA"),
    ("Campbellsville", "KY", "NAIA"),
    ("Carroll (MT)", "MT", "NAIA"),
    ("Central Methodist", "MO", "NAIA"),
    ("Clarke", "IA", "NAIA"),
    ("College of Idaho", "ID", "NAIA"),
    ("Concordia (NE)", "NE", "NAIA"),
    ("Culver-Stockton", "MO", "NAIA"),
    ("Cumberland", "TN", "NAIA"),
    ("Cumberlands", "KY", "NAIA"),
    ("Dakota State", "SD", "NAIA"),
    ("Dakota Wesleyan", "SD", "NAIA"),
    ("Defiance", "OH", "NAIA"),
    ("Dickinson State", "ND", "NAIA"),
    ("Doane", "NE", "NAIA"),
    ("Dordt", "IA", "NAIA"),
    ("Eastern Oregon", "OR", "NAIA"),
    ("Evangel", "MO", "NAIA"),
    ("Faulkner", "AL", "NAIA"),
    ("Florida Memorial", "FL", "NAIA"),
    ("Friends", "KS", "NAIA"),
    ("Georgetown (KY)", "KY", "NAIA"),
    ("Graceland", "IA", "NAIA"),
    ("Grand View", "IA", "NAIA"),
    ("Hastings", "NE", "NAIA"),
    ("Indiana Wesleyan", "IN", "NAIA"),
    ("Judson", "IL", "NAIA"),
    ("Kansas Wesleyan", "KS", "NAIA"),
    ("Keiser", "FL", "NAIA"),
    ("Kentucky Christian", "KY", "NAIA"),
    ("Langston", "OK", "NAIA"),
    ("Lawrence Tech", "MI", "NAIA"),
    ("Lindsey Wilson", "KY", "NAIA"),
    ("Louisiana Christian", "LA", "NAIA"),
    ("Madonna", "MI", "NAIA"),
    ("Marian (IN)", "IN", "NAIA"),
    ("Mayville State", "ND", "NAIA"),
    ("McPherson", "KS", "NAIA"),
    ("MidAmerica Nazarene", "KS", "NAIA"),
    ("Midland", "NE", "NAIA"),
    ("Missouri Baptist", "MO", "NAIA"),
    ("Missouri Valley", "MO", "NAIA"),
    ("Montana State-Northern", "MT", "NAIA"),
    ("Montana Tech", "MT", "NAIA"),
    ("Montana Western", "MT", "NAIA"),
    ("Morningside", "IA", "NAIA"),
    ("Mount Marty", "SD", "NAIA"),
    ("Nelson", "TX", "NAIA"),
    ("Northwestern (IA)", "IA", "NAIA"),
    ("Oklahoma Panhandle State", "OK", "NAIA"),
    ("Olivet Nazarene", "IL", "NAIA"),
    ("Ottawa (AZ)", "AZ", "NAIA"),
    ("Ottawa (KS)", "KS", "NAIA"),
    ("Peru State", "NE", "NAIA"),
    ("Pikeville", "KY", "NAIA"),
    ("Point", "GA", "NAIA"),
    ("Reinhardt", "GA", "NAIA"),
    ("Rio Grande", "OH", "NAIA"),
    ("Rocky Mountain", "MT", "NAIA"),
    ("Saint Francis (IL)", "IL", "NAIA"),
    ("Saint Francis (IN)", "IN", "NAIA"),
    ("Saint Mary (KS)", "KS", "NAIA"),
    ("Saint Thomas (FL)", "FL", "NAIA"),
    ("Saint Xavier", "IL", "NAIA"),
    ("Siena Heights", "MI", "NAIA"),
    ("Simpson (CA)", "CA", "NAIA"),
    ("Southeastern (FL)", "FL", "NAIA"),
    ("Southern Oregon", "OR", "NAIA"),
    ("Southwestern (KS)", "KS", "NAIA"),
    ("St. Ambrose", "IA", "NAIA"),
    ("Sterling", "KS", "NAIA"),
    ("Tabor", "KS", "NAIA"),
    ("Taylor", "IN", "NAIA"),
    ("Texas College", "TX", "NAIA"),
    ("Texas Wesleyan", "TX", "NAIA"),
    ("Thomas (GA)", "GA", "NAIA"),
    ("Union (KY)", "KY", "NAIA"),
    ("Valley City State", "ND", "NAIA"),
    ("Waldorf", "IA", "NAIA"),
    ("Warner", "FL", "NAIA"),
    ("Wayland Baptist", "TX", "NAIA"),
    ("Webber International", "FL", "NAIA"),
    ("William Penn", "IA", "NAIA"),
    ("William Woods", "MO", "NAIA"),
    ("ASA Miami", "FL", "JUCO"),
    ("Blinn", "TX", "JUCO"),
    ("Butler CC", "KS", "JUCO"),
    ("Central Lakes", "MN", "JUCO"),
    ("Cisco", "TX", "JUCO"),
    ("Coahoma CC", "MS", "JUCO"),
    ("Coffeyville CC", "KS", "JUCO"),
    ("College of DuPage", "IL", "JUCO"),
    ("Copiah-Lincoln CC", "MS", "JUCO"),
    ("Dodge City CC", "KS", "JUCO"),
    ("East Central CC", "MS", "JUCO"),
    ("East Mississippi CC", "MS", "JUCO"),
    ("Ellsworth CC", "IA", "JUCO"),
    ("Erie CC", "NY", "JUCO"),
    ("Fond du Lac", "MN", "JUCO"),
    ("Garden City CC", "KS", "JUCO"),
    ("Georgia Military", "GA", "JUCO"),
    ("Highland CC", "KS", "JUCO"),
    ("Hinds CC", "MS", "JUCO"),
    ("Hocking", "OH", "JUCO"),
    ("Holmes CC", "MS", "JUCO"),
    ("Hudson Valley CC", "NY", "JUCO"),
    ("Hutchinson CC", "KS", "JUCO"),
    ("Independence CC", "KS", "JUCO"),
    ("Iowa Central CC", "IA", "JUCO"),
    ("Iowa Western CC", "IA", "JUCO"),
    ("Itasca CC", "MN", "JUCO"),
    ("Itawamba CC", "MS", "JUCO"),
    ("Jones College", "MS", "JUCO"),
    ("Kilgore", "TX", "JUCO"),
    ("Lackawanna", "PA", "JUCO"),
    ("Louisburg", "NC", "JUCO"),
    ("Mesabi Range", "MN", "JUCO"),
    ("Minnesota State CTC", "MN", "JUCO"),
    ("Minnesota West CTC", "MN", "JUCO"),
    ("Mississippi Delta CC", "MS", "JUCO"),
    ("Mississippi Gulf Coast CC", "MS", "JUCO"),
    ("Monroe CC", "NY", "JUCO"),
    ("Nassau CC", "NY", "JUCO"),
    ("Navarro", "TX", "JUCO"),
    ("New Mexico Military", "NM", "JUCO"),
    ("North Dakota State CS", "ND", "JUCO"),
    ("Northeast Mississippi CC", "MS", "JUCO"),
    ("Northeastern Oklahoma A&M", "OK", "JUCO"),
    ("Northwest Mississippi CC", "MS", "JUCO"),
    ("Onondaga CC", "NY", "JUCO"),
    ("Pearl River CC", "MS", "JUCO"),
    ("Rochester CTC", "MN", "JUCO"),
    ("Snow", "UT", "JUCO"),
    ("Southwest Mississippi CC", "MS", "JUCO"),
    ("Trinity Valley CC", "TX", "JUCO"),
    ("Tyler JC", "TX", "JUCO"),
    ("Vermilion CC", "MN", "JUCO"),
    ("Allan Hancock", "CA", "JUCO"),
    ("American River", "CA", "JUCO"),
    ("Antelope Valley", "CA", "JUCO"),
    ("Bakersfield", "CA", "JUCO"),
    ("Butte", "CA", "JUCO"),
    ("Cabrillo", "CA", "JUCO"),
    ("Cerritos", "CA", "JUCO"),
    ("Chabot", "CA", "JUCO"),
    ("Chaffey", "CA", "JUCO"),
    ("Citrus", "CA", "JUCO"),
    ("City College of San Francisco", "CA", "JUCO"),
    ("College of San Mateo", "CA", "JUCO"),
    ("College of the Canyons", "CA", "JUCO"),
    ("College of the Desert", "CA", "JUCO"),
    ("College of the Redwoods", "CA", "JUCO"),
    ("College of the Sequoias", "CA", "JUCO"),
    ("Community Christian", "CA", "JUCO"),
    ("Compton", "CA", "JUCO"),
    ("Contra Costa", "CA", "JUCO"),
    ("De Anza", "CA", "JUCO"),
    ("Diablo Valley", "CA", "JUCO"),
    ("East Los Angeles", "CA", "JUCO"),
    ("El Camino", "CA", "JUCO"),
    ("Feather River", "CA", "JUCO"),
    ("Foothill", "CA", "JUCO"),
    ("Fresno City", "CA", "JUCO"),
    ("Fullerton", "CA", "JUCO"),
    ("Gavilan", "CA", "JUCO"),
    ("Glendale (CA)", "CA", "JUCO"),
    ("Golden West", "CA", "JUCO"),
    ("Grossmont", "CA", "JUCO"),
    ("Hartnell", "CA", "JUCO"),
    ("Laney", "CA", "JUCO"),
    ("Long Beach City", "CA", "JUCO"),
    ("Los Angeles Harbor", "CA", "JUCO"),
    ("Los Angeles Pierce", "CA", "JUCO"),
    ("Los Angeles Southwest", "CA", "JUCO"),
    ("Los Angeles Valley", "CA", "JUCO"),
    ("Los Medanos", "CA", "JUCO"),
    ("Merced", "CA", "JUCO"),
    ("Modesto", "CA", "JUCO"),
    ("Monterey Peninsula", "CA", "JUCO"),
    ("Moorpark", "CA", "JUCO"),
    ("Mt. San Antonio", "CA", "JUCO"),
    ("Mt. San Jacinto", "CA", "JUCO"),
    ("Orange Coast", "CA", "JUCO"),
    ("Palomar", "CA", "JUCO"),
    ("Pasadena City", "CA", "JUCO"),
    ("Reedley", "CA", "JUCO"),
    ("Riverside City", "CA", "JUCO"),
    ("Sacramento City", "CA", "JUCO"),
    ("Saddleback", "CA", "JUCO"),
    ("San Bernardino Valley", "CA", "JUCO"),
    ("San Diego Mesa", "CA", "JUCO"),
    ("San Joaquin Delta", "CA", "JUCO"),
    ("San Jose City", "CA", "JUCO"),
    ("Santa Ana", "CA", "JUCO"),
    ("Santa Barbara City", "CA", "JUCO"),
    ("Santa Monica", "CA", "JUCO"),
    ("Santa Rosa", "CA", "JUCO"),
    ("Shasta", "CA", "JUCO"),
    ("Sierra", "CA", "JUCO"),
    ("Southwestern (CA)", "CA", "JUCO"),
    ("Ventura", "CA", "JUCO"),
    ("Victor Valley", "CA", "JUCO"),
    ("West Hills Coalinga", "CA", "JUCO"),
    ("West Los Angeles", "CA", "JUCO"),
]

@app.get("/api/colleges")
async def list_colleges(request: Request):
    """Return the full NCAA college football list."""
    return JSONResponse(sorted(set(ALL_COLLEGES)))

@app.get("/api/colleges/by-state")
async def colleges_by_state(state: str = ""):
    """Return colleges in a state grouped by division."""
    if not state:
        # Return all unique states
        states = sorted(set(c[1] for c in COLLEGES_BY_STATE))
        return JSONResponse({"states": states})
    matching = [c for c in COLLEGES_BY_STATE if c[1].upper() == state.upper()]
    grouped = {}
    for name, st, div in matching:
        grouped.setdefault(div, []).append(name)
    for div in grouped:
        grouped[div].sort()
    # Order divisions FBS, FCS, D2, D3, NAIA, JUCO
    ordered = {}
    for div in ["FBS", "FCS", "D2", "D3", "NAIA", "JUCO"]:
        if div in grouped:
            ordered[div] = grouped[div]
    return JSONResponse({"state": state.upper(), "divisions": ordered})

@app.get("/api/highschools/search")
async def search_highschools(q: str = "", db: Session = Depends(get_db)):
    """Search high schools by name (partial match, any state)."""
    if not q or len(q) < 2:
        return JSONResponse([])
    from sqlalchemy import text as _text
    rows = db.execute(
        _text("SELECT name, city, state FROM schools WHERE name LIKE :q ORDER BY name LIMIT 20"),
        {"q": f"%{q}%"}
    ).fetchall()
    return JSONResponse([{"name": r[0], "city": r[1], "state": r[2], "label": f"{r[0]} — {r[1]}, {r[2]}"} for r in rows])

def _analytics_parse_float(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    try:
        return float(s)
    except (TypeError, ValueError):
        return None

def _analytics_parse_height_inches(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    if "'" in s:
        parts = s.replace('"', '').split("'")
        try:
            ft = int(parts[0]) if parts[0] else 0
            inches = int(parts[1]) if len(parts) > 1 and parts[1] else 0
            return ft * 12 + inches
        except (TypeError, ValueError):
            return None
    try:
        return float(s)
    except (TypeError, ValueError):
        return None

def _analytics_median(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return None
    vals = sorted(vals)
    n = len(vals)
    mid = n // 2
    if n % 2 == 1:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) / 2.0

def _analytics_format_height(inches):
    if inches is None:
        return "—"
    ft = int(inches) // 12
    inch = int(round(inches)) % 12
    return f"{ft}'{inch}\""

def _analytics_load_players(db: Session, grad_year: str, state: str, position: str):
    query = db.query(User, PlayerProfile).join(PlayerProfile, User.id == PlayerProfile.user_id).filter(User.role == "player")
    if grad_year:
        query = query.filter(PlayerProfile.year == grad_year)
    if state:
        query = query.filter(PlayerProfile.state.ilike(state))
    if position:
        query = query.filter(PlayerProfile.position == position)
    rows = query.all()
    user_ids = [u.id for u, _ in rows]
    verified_by_user = {}
    if user_ids:
        vrows = db.query(VerifiedStat.player_id, VerifiedStat.stat_field).filter(VerifiedStat.player_id.in_(user_ids)).all()
        for pid, field in vrows:
            verified_by_user.setdefault(pid, set()).add(field)
    players = []
    for u, p in rows:
        name = f"{(p.first_name or '').strip()} {(p.last_name or '').strip()}".strip() or u.username
        vset = verified_by_user.get(u.id, set())
        players.append({
            "user_id": u.id,
            "username": u.username,
            "name": name,
            "school": (p.school or "").strip() or "Unknown School",
            "state": (p.state or "").strip(),
            "position": (p.position or "").strip(),
            "grad_year": (p.year or "").strip(),
            "gpa": _analytics_parse_float(p.gpa),
            "height_in": _analytics_parse_height_inches(p.height),
            "weight": _analytics_parse_float(p.weight),
            "forty": _analytics_parse_float(p.forty_yard),
            "bench": _analytics_parse_float(p.bench_press),
            "vertical": _analytics_parse_float(p.vertical),
            "squat": _analytics_parse_float(p.squat),
            "clean": _analytics_parse_float(p.clean),
            "broad_jump_in": _analytics_parse_height_inches(p.broad_jump),
            "pro_agility": _analytics_parse_float(p.pro_agility),
            "wingspan": _analytics_parse_float(p.wingspan),
            "biggest_factors": (p.biggest_factors or "").split(",") if p.biggest_factors else [],
            "v_forty": "forty_yard" in vset,
            "v_bench": "bench_press" in vset,
            "v_vertical": "vertical" in vset,
            "v_gpa": "gpa" in vset,
            "v_height": "height" in vset,
            "v_weight": "weight" in vset,
            "v_wingspan": "wingspan" in vset,
            "v_squat": "squat" in vset,
            "v_clean": "clean" in vset,
            "v_broad_jump": "broad_jump" in vset,
            "v_pro_agility": "pro_agility" in vset,
        })
    return players

def _analytics_top_n(players, key, reverse, n=10):
    filtered = [p for p in players if p.get(key) is not None]
    filtered.sort(key=lambda p: p[key], reverse=reverse)
    return filtered[:n]

def _analytics_school_aggregates(players, min_n=3):
    from collections import defaultdict
    groups = defaultdict(list)
    for p in players:
        groups[p["school"]].append(p)
    rows = []
    for school, plist in groups.items():
        n = len(plist)
        if n < min_n:
            continue
        rows.append({
            "school": school,
            "state": plist[0].get("state") or "",
            "n": n,
            "med_gpa": _analytics_median([p["gpa"] for p in plist]),
            "med_height_in": _analytics_median([p["height_in"] for p in plist]),
            "med_weight": _analytics_median([p["weight"] for p in plist]),
            "med_forty": _analytics_median([p["forty"] for p in plist]),
            "med_bench": _analytics_median([p["bench"] for p in plist]),
            "med_vertical": _analytics_median([p["vertical"] for p in plist]),
        })
    rows.sort(key=lambda r: -r["n"])
    return rows

def _analytics_histogram(values, buckets):
    """buckets is a list of (low, high, label)."""
    counts = [0] * len(buckets)
    for v in values:
        if v is None:
            continue
        for i, (lo, hi, _label) in enumerate(buckets):
            if lo <= v < hi:
                counts[i] += 1
                break
    return [{"label": buckets[i][2], "count": counts[i]} for i in range(len(buckets))]

def _analytics_factors_breakdown(players):
    labels = {
        "location": "Location",
        "winning_tradition": "Winning Tradition",
        "education": "Education",
        "player_development": "Player Development",
        "opportunity_to_play": "Opportunity to Play",
        "cost": "Cost",
        "school_size": "School Size",
        "job_placement": "Job Placement",
        "facilities": "Facilities",
    }
    counts = {k: 0 for k in labels}
    total = 0
    for p in players:
        picked = [f for f in p["biggest_factors"] if f in labels]
        if picked:
            total += 1
        for f in picked:
            counts[f] += 1
    out = []
    for k, label in labels.items():
        pct = (counts[k] / total * 100.0) if total > 0 else 0.0
        out.append({"key": k, "label": label, "count": counts[k], "pct": pct})
    out.sort(key=lambda r: -r["count"])
    return out, total

@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse("/login", status_code=302)
    _is_premium_player = user.role == "player" and tier_gte(user.subscription_tier, "premium")
    if user.role != "coach" and not user.is_admin and not _is_premium_player:
        return RedirectResponse("/dashboard", status_code=302)

    grad_year = (request.query_params.get("grad_year") or "").strip()
    state = (request.query_params.get("state") or "").strip().upper()
    position = (request.query_params.get("position") or "").strip()

    players = _analytics_load_players(db, grad_year, state, position)

    leaderboards = {
        "fastest_40": _analytics_top_n(players, "forty", reverse=False),
        "bench": _analytics_top_n(players, "bench", reverse=True),
        "vertical": _analytics_top_n(players, "vertical", reverse=True),
        "gpa": _analytics_top_n(players, "gpa", reverse=True),
        "tallest": _analytics_top_n(players, "height_in", reverse=True),
        "heaviest": _analytics_top_n(players, "weight", reverse=True),
        "wingspan": _analytics_top_n(players, "wingspan", reverse=True),
        "squat": _analytics_top_n(players, "squat", reverse=True),
        "clean": _analytics_top_n(players, "clean", reverse=True),
        "broad_jump": _analytics_top_n(players, "broad_jump_in", reverse=True),
        "pro_agility": _analytics_top_n(players, "pro_agility", reverse=False),
    }

    school_rows = _analytics_school_aggregates(players, min_n=3)

    gpa_hist = _analytics_histogram(
        [p["gpa"] for p in players],
        [(0.0, 2.0, "< 2.0"), (2.0, 2.5, "2.0–2.5"), (2.5, 3.0, "2.5–3.0"),
         (3.0, 3.5, "3.0–3.5"), (3.5, 4.0, "3.5–4.0"), (4.0, 5.1, "4.0+")],
    )
    forty_hist = _analytics_histogram(
        [p["forty"] for p in players],
        [(0.0, 4.4, "< 4.4"), (4.4, 4.5, "4.4–4.5"), (4.5, 4.6, "4.5–4.6"),
         (4.6, 4.7, "4.6–4.7"), (4.7, 4.9, "4.7–4.9"), (4.9, 10.0, "4.9+")],
    )

    from collections import Counter, defaultdict
    position_counts = Counter(p["position"] for p in players if p["position"])
    position_breakdown = sorted(position_counts.items(), key=lambda kv: -kv[1])
    state_counts = Counter(p["state"] for p in players if p["state"])
    state_breakdown = sorted(state_counts.items(), key=lambda kv: -kv[1])[:10]

    # Top 40 times broken out by position
    pos_groups = defaultdict(list)
    for p in players:
        if p["position"]:
            pos_groups[p["position"]].append(p)
    pos_forty_lb = []
    pos_bench_lb = []
    for pos in sorted(pos_groups.keys()):
        top_forty = sorted(
            [q for q in pos_groups[pos] if q["forty"] is not None],
            key=lambda q: q["forty"],
        )[:5]
        if top_forty:
            pos_forty_lb.append((pos, top_forty))
        top_bench = sorted(
            [q for q in pos_groups[pos] if q["bench"] is not None],
            key=lambda q: -q["bench"],
        )[:5]
        if top_bench:
            pos_bench_lb.append((pos, top_bench))

    factors, factors_total = _analytics_factors_breakdown(players)

    # Distinct filter options (from existing data)
    all_states = sorted({p["state"] for p in players if p["state"]})
    all_positions = sorted({p["position"] for p in players if p["position"]})

    return templates.TemplateResponse("analytics.html", {
        "request": request, "user": user,
        "grad_year": grad_year, "state": state, "position": position,
        "total_players": len(players),
        "leaderboards": leaderboards,
        "pos_forty_lb": pos_forty_lb,
        "pos_bench_lb": pos_bench_lb,
        "school_rows": school_rows,
        "gpa_hist": gpa_hist,
        "forty_hist": forty_hist,
        "position_breakdown": position_breakdown,
        "state_breakdown": state_breakdown,
        "factors": factors,
        "factors_total": factors_total,
        "all_states": all_states,
        "all_positions": all_positions,
        "format_height": _analytics_format_height,
    })

@app.get("/analytics/export.csv")
async def analytics_export_csv(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user:
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    _is_premium_player = user.role == "player" and tier_gte(user.subscription_tier, "premium")
    if user.role != "coach" and not user.is_admin and not _is_premium_player:
        return JSONResponse({"error": "Not authorized"}, status_code=403)
    grad_year = (request.query_params.get("grad_year") or "").strip()
    state = (request.query_params.get("state") or "").strip().upper()
    position = (request.query_params.get("position") or "").strip()
    players = _analytics_load_players(db, grad_year, state, position)
    school_rows = _analytics_school_aggregates(players, min_n=3)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["School", "State", "Players", "Median GPA", "Median Height", "Median Weight",
                     "Median 40", "Median Bench", "Median Vertical"])
    for r in school_rows:
        writer.writerow([
            r["school"], r["state"], r["n"],
            f"{r['med_gpa']:.2f}" if r["med_gpa"] is not None else "",
            _analytics_format_height(r["med_height_in"]) if r["med_height_in"] is not None else "",
            f"{r['med_weight']:.0f}" if r["med_weight"] is not None else "",
            f"{r['med_forty']:.2f}" if r["med_forty"] is not None else "",
            f"{r['med_bench']:.0f}" if r["med_bench"] is not None else "",
            f"{r['med_vertical']:.0f}" if r["med_vertical"] is not None else "",
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="analytics-schools-{datetime.utcnow().strftime("%Y%m%d")}.csv"'},
    )

@app.get("/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse("/login", status_code=302)
    cutoff = datetime.utcnow() - timedelta(days=7)
    notifs = db.query(Notification).filter(
        Notification.user_id == user_id,
        Notification.created_at >= cutoff,
    ).order_by(Notification.created_at.desc()).limit(200).all()
    # Mark all unread as read on open
    db.query(Notification).filter(
        Notification.user_id == user_id,
        Notification.is_read == False,
    ).update({"is_read": True})
    db.commit()
    return templates.TemplateResponse("notifications.html", {
        "request": request,
        "user": user,
        "notifications": notifs,
    })

@app.get("/api/notifications/unread-count")
async def notifications_unread_count(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"count": 0})
    cutoff = datetime.utcnow() - timedelta(days=7)
    count = db.query(Notification).filter(
        Notification.user_id == user_id,
        Notification.is_read == False,
        Notification.created_at >= cutoff,
    ).count()
    return JSONResponse({"count": count})

@app.get("/dashboard/scout/search-players")
async def scout_search_players(
    request: Request,
    q: str = "",
    forty_bucket: str = "",
    grad_year: str = "",
    position: str = "",
    state: str = "",
    city: str = "",
    school: str = "",
    db: Session = Depends(get_db),
):
    """Search platform players to add to the board. Accepts name query OR filters."""
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or (user.role != "coach" and not user.is_admin):
        return JSONResponse({"error": "Not authorized"}, status_code=403)

    query = db.query(User, PlayerProfile).join(PlayerProfile, User.id == PlayerProfile.user_id).filter(User.role == "player")
    q = (q or "").strip()

    if q:
        if len(q) < 2:
            return JSONResponse([])
        like = f"%{q}%"
        query = query.filter(
            (User.username.ilike(like)) | (PlayerProfile.first_name.ilike(like)) | (PlayerProfile.last_name.ilike(like))
        )
        results = query.limit(25).all()
    else:
        if not any([forty_bucket, grad_year, position, state, city, school]):
            return JSONResponse([])
        if grad_year:
            query = query.filter(PlayerProfile.year == grad_year)
        if position:
            query = query.filter(PlayerProfile.position == position)
        if state:
            query = query.filter(PlayerProfile.state.ilike(state))
        if city:
            query = query.filter(PlayerProfile.city.ilike(city))
        if school:
            query = query.filter(PlayerProfile.school.ilike(school))
        rows = query.limit(200).all()
        if forty_bucket:
            def in_bucket(val):
                try:
                    f = float(val)
                except (TypeError, ValueError):
                    return False
                if forty_bucket == "u44":
                    return f < 4.4
                if forty_bucket == "44_45":
                    return 4.4 <= f < 4.5
                if forty_bucket == "45_47":
                    return 4.5 <= f < 4.7
                if forty_bucket == "o47":
                    return f >= 4.7
                return True
            rows = [(u, p) for (u, p) in rows if in_bucket(p.forty_yard)]
        results = rows[:25]

    college = _coach_college(user, db)
    on_board_ids = set()
    if college and results:
        ids = [u.id for u, _ in results]
        rows = db.query(ScoutBoardCard.player_user_id).filter(
            ScoutBoardCard.college == college,
            ScoutBoardCard.player_user_id.in_(ids),
            ScoutBoardCard.archived_at.is_(None),
        ).all()
        on_board_ids = {r[0] for r in rows}
    return JSONResponse([{
        "user_id": u.id,
        "name": f"{p.first_name} {p.last_name}".strip() or u.username,
        "school": p.school or "",
        "position": p.position or "",
        "grad_year": p.year or "",
        "forty_yard": p.forty_yard or "",
        "photo": p.photo or "",
        "on_board": u.id in on_board_ids,
    } for u, p in results])

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
