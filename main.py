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
from datetime import datetime
from typing import Optional, Dict, List

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

app.add_middleware(SessionMiddleware, secret_key="bearcats-recruiting-secret-2024-xK9mP")

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
    created_at = Column(DateTime, default=datetime.utcnow)

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

Base.metadata.create_all(bind=engine)

# ── Helpers ────────────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="/home/recruiting/bearcats/static"), name="static")
templates = Jinja2Templates(directory="/home/recruiting/bearcats/templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


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
async def signup_get(request: Request, db: Session = Depends(get_db), invite: str = None):
    teams = db.query(Team).order_by(Team.name).all()
    invite_valid = False
    invite_error = None
    if invite:
        inv = db.query(CoachInvite).filter(CoachInvite.token == invite, CoachInvite.used == False).first()
        if inv and inv.expires_at > datetime.utcnow():
            invite_valid = True
        else:
            invite_error = "This invite link is invalid or has expired."
    return templates.TemplateResponse("signup.html", {
        "request": request, "error": invite_error, "teams": teams,
        "selected_team_id": None, "invite_token": invite if invite_valid else None,
        "invite_valid": invite_valid
    })

@app.post("/signup", response_class=HTMLResponse)
async def signup_post(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("player"),
    tier: str = Form("essentials"),
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
    db: Session = Depends(get_db)
):
    username = username.strip()
    new_team_name = new_team_name.strip()
    teams = db.query(Team).order_by(Team.name).all()

    def err(msg):
        return templates.TemplateResponse("signup.html", {
            "request": request, "error": msg,
            "teams": teams, "selected_team_id": team_id,
            "selected_tier": tier,
            "invite_token": invite_token, "invite_valid": False,
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
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return err("Username can only contain letters, numbers, underscores, dots, and hyphens (no spaces).")
    if db.query(User).filter(User.username == username).first():
        return err("Username already taken.")
    if db.query(User).filter(User.email == email).first():
        return err("Email already registered.")
    if len(password) < 6:
        return err("Password must be at least 6 characters.")

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

    user = User(username=username, email=email, password_hash=hash_password(password), role=role)
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
    request.session["user_id"] = user.id
    request.session["is_admin"] = bool(user.is_admin)
    request.session["role"] = user.role
    if role == "player":
        import asyncio
        asyncio.create_task(send_player_signup_notification(user.username, user.email, school_name.strip()))
        # Create Stripe customer and checkout session immediately
        _tier = tier if tier in STRIPE_PRICES and STRIPE_PRICES[tier] else "essentials"
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
                line_items=[{"price": STRIPE_PRICES[_tier], "quantity": 1}],
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
        print(f"Email send error: {e}")

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
    # Always show success to prevent email enumeration
    if user:
        import secrets as _secrets
        from datetime import timedelta
        token_str = _secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=1)
        db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id, PasswordResetToken.used == 0).delete()
        db.add(PasswordResetToken(user_id=user.id, token=token_str, expires_at=expires))
        db.commit()
        reset_url = f"{SITE_URL}/reset-password/{token_str}"
        await send_reset_email(email, reset_url)
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
    if len(password) < 8:
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "invalid": False, "success": False, "error": "Password must be at least 8 characters."})
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
    user = db.query(User).filter((User.username == username) | (User.email == username)).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password."})
    request.session["user_id"] = user.id
    request.session["is_admin"] = bool(user.is_admin)
    request.session["role"] = user.role
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/logout")
async def logout(request: Request):
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
            player_data.append({"user": p, "profile": prof, "tier": p.subscription_tier or "free"})

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
    return templates.TemplateResponse("edit_profile.html", {"request": request, "user": user, "profile": profile, "success": success, "teams": teams, "videos": videos, "video_error": video_error, "transcripts": transcripts, "transcript_error": transcript_error})

@app.post("/profile/edit", response_class=HTMLResponse)
async def edit_profile_post(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()
    form = await request.form()

    if user.role == "player":
        p = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
        p.first_name = form.get("first_name", "")
        p.last_name = form.get("last_name", "")
        p.position = form.get("position", "")
        p.year = form.get("year", "")
        p.height = form.get("height", "")
        p.weight = form.get("weight", "")
        p.forty_yard = form.get("forty_yard", "")
        p.bench_press = form.get("bench_press", "")
        p.vertical = form.get("vertical", "")
        p.squat = form.get("squat", "")
        p.clean = form.get("clean", "")
        _bj_ft = form.get("broad_jump_feet", "").strip()
        _bj_in = form.get("broad_jump_inches", "").strip()
        if _bj_ft or _bj_in:
            p.broad_jump = str(_bj_ft or 0) + "'" + str(_bj_in or 0) + '"'
        else:
            p.broad_jump = ""
        p.pro_agility = form.get("pro_agility", "")
        p.wingspan = form.get("wingspan", "")
        p.gpa = form.get("gpa", "")
        p.school = form.get("school", "")
        p.bio = form.get("bio", "")
        p.link1_label = form.get("link1_label", "")
        p.link1_url = form.get("link1_url", "")
        p.link2_label = form.get("link2_label", "")
        p.link2_url = form.get("link2_url", "")
        p.link3_label = form.get("link3_label", "")
        p.link3_url = form.get("link3_url", "")
        p.offer1 = form.get("offer1", "")
        p.offer2 = form.get("offer2", "")
        p.offer3 = form.get("offer3", "")
        p.offer4 = form.get("offer4", "")
        p.offer5 = form.get("offer5", "")
        for i in range(1, 6):
            setattr(p, f"visit{i}_school", form.get(f"visit{i}_school", ""))
            setattr(p, f"visit{i}_date",   form.get(f"visit{i}_date",   ""))
        p.hudl_url = form.get("hudl_url", "")
        p.x_url = form.get("x_url", "")
        p.instagram_url = form.get("instagram_url", "")
        p.phone = form.get("phone", "")
        p.contact_email = form.get("contact_email", "")
        p.intended_major = form.get("intended_major", "")
    else:
        c = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
        c.first_name = form.get("first_name", "")
        c.last_name = form.get("last_name", "")
        c.school = form.get("school", "")
        c.title = form.get("title", "")
        c.division = form.get("division", "")
        c.conference = form.get("conference", "")
        c.bio = form.get("bio", "")
        c.link1_label = form.get("link1_label", "")
        c.link1_url = form.get("link1_url", "")
        c.link2_label = form.get("link2_label", "")
        c.link2_url = form.get("link2_url", "")
        c.phone = form.get("phone", "")
        c.contact_email = form.get("contact_email", "")
    db.commit()

    if user.role == "player":
        profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
    else:
        profile = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
    teams = db.query(Team).order_by(Team.name).all()
    videos = db.query(Video).filter(Video.user_id == user_id).order_by(Video.is_pinned.desc(), Video.created_at.desc()).all()
    transcripts = db.query(Transcript).filter(Transcript.user_id == user_id).order_by(Transcript.created_at.desc()).all() if user.role == "player" else []
    return templates.TemplateResponse("edit_profile.html", {"request": request, "user": user, "profile": profile, "success": True, "teams": teams, "videos": videos, "video_error": None, "transcripts": transcripts, "transcript_error": None})

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
            eval_list.append({"coach_name": coach_name, "date": fmt_date, "content": ev.content})

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
                        from datetime import datetime as _dt
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
    logged_in = db.query(User).filter(User.id == user_id).first()

    # Allow admin to upload video for another user
    if target_user_id.strip().isdigit() and logged_in and logged_in.is_admin:
        upload_user_id = int(target_user_id.strip())
    else:
        upload_user_id = user_id

    ext = video.filename.rsplit(".", 1)[-1].lower() if "." in video.filename else ""
    if ext not in VIDEO_ALLOWED_EXTENSIONS:
        return RedirectResponse(redirect_to + "?video_error=type", status_code=302)

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
                ExtraArgs={"ACL": "public-read", "ContentType": content_type}
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
    redirect_to = form.get("redirect_to", f"/profile/{user.username}")
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
    redirect_to = form.get("redirect_to", f"/profile/{logged_in.username}")
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
    redirect_to = str(form.get("redirect_to", ""))
    back = redirect_to or "/profile/edit"

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
                ExtraArgs={"ACL": "public-read", "ContentType": content_type}
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
    redirect_to = form.get("redirect_to", "/profile/edit")
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

    import io
    key = f"transcripts/{target_user_id}/{uuid.uuid4().hex}.{ext}"
    try:
        s3.upload_fileobj(
            io.BytesIO(contents),
            SPACES_BUCKET,
            key,
            ExtraArgs={"ACL": "public-read", "ContentType": TRANSCRIPT_CONTENT_TYPES.get(ext, "application/octet-stream")}
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
    redirect_to = form.get("redirect_to", "/profile/edit")
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
    if ext == "pdf":
        viewer_url = t.file_url
    else:
        from urllib.parse import quote
        viewer_url = "https://docs.google.com/viewer?url=" + quote(t.file_url, safe="") + "&embedded=true"
    title = t.title or t.filename or "Transcript"
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset='UTF-8'>
  <title>{title}</title>
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
    <h2>{title}</h2>
    <a href='/profile/transcripts/{transcript_id}/download'>Download</a>
  </div>
  <iframe src='{viewer_url}'></iframe>
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
    content = (form.get("content") or "").strip()
    if content:
        db.add(Evaluation(player_id=player.id, coach_id=coach.id, content=content))
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
        profile.stars = stars
        db.commit()
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
        target.subscription_tier = tier
        db.commit()
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
        "success": False, "error": None
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
        p.first_name = form.get("first_name", "")
        p.last_name = form.get("last_name", "")
        p.position = form.get("position", "")
        p.year = form.get("year", "")
        p.height = form.get("height", "")
        p.weight = form.get("weight", "")
        p.forty_yard = form.get("forty_yard", "")
        p.bench_press = form.get("bench_press", "")
        p.vertical = form.get("vertical", "")
        p.squat = form.get("squat", "")
        p.clean = form.get("clean", "")
        _bj_ft = form.get("broad_jump_feet", "").strip()
        _bj_in = form.get("broad_jump_inches", "").strip()
        if _bj_ft or _bj_in:
            p.broad_jump = str(_bj_ft or 0) + "'" + str(_bj_in or 0) + '"'
        else:
            p.broad_jump = ""
        p.pro_agility = form.get("pro_agility", "")
        p.wingspan = form.get("wingspan", "")
        p.gpa = form.get("gpa", "")
        p.school = form.get("school", "")
        p.bio = form.get("bio", "")
        p.hudl_url = form.get("hudl_url", "")
        p.x_url = form.get("x_url", "")
        p.instagram_url = form.get("instagram_url", "")
        p.phone = form.get("phone", "")
        p.contact_email = form.get("contact_email", "")
        p.offer1 = form.get("offer1", "")
        p.offer2 = form.get("offer2", "")
        p.offer3 = form.get("offer3", "")
        p.offer4 = form.get("offer4", "")
        p.offer5 = form.get("offer5", "")
        for i in range(1, 6):
            setattr(p, f"visit{i}_school", form.get(f"visit{i}_school", ""))
            setattr(p, f"visit{i}_date", form.get(f"visit{i}_date", ""))
        p.ncaa_eligibility_num = form.get("ncaa_eligibility_num", "")
        p.intended_major = form.get("intended_major", "")
    else:
        c = db.query(CoachProfile).filter(CoachProfile.user_id == target_id).first()
        c.first_name = form.get("first_name", "")
        c.last_name = form.get("last_name", "")
        c.school = form.get("school", "")
        c.title = form.get("title", "")
        c.division = form.get("division", "")
        c.conference = form.get("conference", "")
        c.bio = form.get("bio", "")
        c.phone = form.get("phone", "")
        c.contact_email = form.get("contact_email", "")
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
    return templates.TemplateResponse("admin_invites.html", {
        "request": request,
        "invites": invites,
        "used_by_users": used_by_users,
        "site_url": site_url,
        "now": datetime.utcnow(),
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
    db.query(PlayerProfile).filter(PlayerProfile.user_id == target_id).delete()
    db.query(CoachProfile).filter(CoachProfile.user_id == target_id).delete()
    db.query(Message).filter((Message.sender_id == target_id) | (Message.receiver_id == target_id)).delete()
    db.query(Video).filter(Video.user_id == target_id).delete()
    db.query(Transcript).filter(Transcript.user_id == target_id).delete()
    db.query(Evaluation).filter((Evaluation.coach_id == target_id) | (Evaluation.player_id == target_id)).delete()
    db.delete(target)
    db.commit()
    return RedirectResponse("/dashboard", status_code=302)


@app.get("/messages", response_class=HTMLResponse)
async def messages_inbox(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)
    user = db.query(User).filter(User.id == user_id).first()

    from sqlalchemy import or_

    # Single query: all messages where user is sender OR receiver
    all_msgs = db.query(Message).filter(
        or_(Message.sender_id == user_id, Message.receiver_id == user_id)
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
                (Message.sender_id == user_id) & (Message.receiver_id == pid),
                (Message.sender_id == pid) & (Message.receiver_id == user_id)
            )
        ).order_by(Message.timestamp.desc()).first()
        unread = db.query(Message).filter(
            Message.sender_id == pid,
            Message.receiver_id == user_id,
            Message.read == False
        ).count()
        conversations.append({"peer": peer, "last_msg": last_msg, "unread": unread})

    conversations.sort(key=lambda x: x["last_msg"].timestamp if x["last_msg"] else datetime.min, reverse=True)
    total_unread = unread_sender_count(db, user_id)
    return templates.TemplateResponse("messages.html", {
        "request": request,
        "user": user,
        "conversations": conversations,
        "unread_count": total_unread
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
        ((Message.sender_id == user_id) & (Message.receiver_id == peer.id)) |
        ((Message.sender_id == peer.id) & (Message.receiver_id == user_id))
    ).order_by(Message.timestamp.asc()).all()

    for m in msgs:
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



@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    # Verify the user owns this connection via session cookie
    session_id = websocket.cookies.get("session")
    if not session_id:
        await websocket.close(code=4001)
        return

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        await websocket.close(code=4001)
        return

    await manager.connect(user_id, websocket)
    try:
        while True:
            # Keep connection alive; actual sending is done server-side via manager
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)

UPLOAD_DIR = "/home/recruiting/bearcats/static/uploads"
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

    # Allow admin to upload photo for another user via target_user_id form field
    logged_in_user = db.query(User).filter(User.id == user_id).first()
    if target_user_id.strip().isdigit() and logged_in_user and logged_in_user.is_admin:
        target_user_id = int(target_user_id.strip())
    else:
        target_user_id = user_id

    filename = f"{target_user_id}_{uuid.uuid4().hex[:8]}.{ext}"
    filepath = os.path.join(UPLOAD_DIR, filename)

    with open(filepath, "wb") as f:
        f.write(contents)

    target_user = db.query(User).filter(User.id == target_user_id).first()
    if target_user and target_user.role == "player":
        p = db.query(PlayerProfile).filter(PlayerProfile.user_id == target_user_id).first()
        if p is None:
            p = PlayerProfile(user_id=target_user_id)
            db.add(p)
        if p.photo and os.path.exists(os.path.join(UPLOAD_DIR, os.path.basename(p.photo))):
            try:
                os.remove(os.path.join(UPLOAD_DIR, os.path.basename(p.photo)))
            except:
                pass
        p.photo = f"/static/uploads/{filename}"
    else:
        c = db.query(CoachProfile).filter(CoachProfile.user_id == target_user_id).first()
        if c is None:
            c = CoachProfile(user_id=target_user_id)
            db.add(c)
        if c.photo and os.path.exists(os.path.join(UPLOAD_DIR, os.path.basename(c.photo))):
            try:
                os.remove(os.path.join(UPLOAD_DIR, os.path.basename(c.photo)))
            except:
                pass
        c.photo = f"/static/uploads/{filename}"
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
    redirect_to = form.get("redirect_to", "/profile/edit")
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
    peer = db.query(User).filter(User.username == username).first()
    if not peer:
        raise HTTPException(status_code=404)
    form = await request.form()
    text = form.get("content", "").strip()
    if text:
        msg = Message(sender_id=user_id, receiver_id=peer.id, content=text)
        db.add(msg)
        db.commit()
        db.refresh(msg)

        sender = db.query(User).filter(User.id == user_id).first()
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
    peer = db.query(User).filter(User.username == username).first()
    if not peer:
        return JSONResponse({"error": "User not found"}, status_code=404)
    data = await request.json()
    text = data.get("content", "").strip()
    if not text:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    msg = Message(sender_id=user_id, receiver_id=peer.id, content=text)
    db.add(msg)
    db.commit()
    db.refresh(msg)

    sender = db.query(User).filter(User.id == user_id).first()
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

# ── Stripe Routes ──────────────────────────────────────────────────────────────

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
    if tier not in STRIPE_PRICES or not STRIPE_PRICES[tier]:
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
        line_items=[{"price": STRIPE_PRICES[tier], "quantity": 1}],
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
    try:
        if STRIPE_WEBHOOK_SECRET:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        else:
            import json
            event = stripe.Event.construct_from(json.loads(payload), stripe.api_key)
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

@app.get("/api/schools/states")
def schools_states():
    conn = sqlite3.connect("/home/recruiting/bearcats/recruiting.db")
    rows = conn.execute("SELECT DISTINCT state FROM schools ORDER BY state").fetchall()
    conn.close()
    return JSONResponse([r[0] for r in rows])

@app.get("/api/schools/cities")
def schools_cities(state: str):
    conn = sqlite3.connect("/home/recruiting/bearcats/recruiting.db")
    rows = conn.execute("SELECT DISTINCT city FROM schools WHERE state=? ORDER BY city", (state.upper(),)).fetchall()
    conn.close()
    return JSONResponse([r[0] for r in rows])

@app.get("/api/schools/list")
def schools_list(state: str, city: str):
    conn = sqlite3.connect("/home/recruiting/bearcats/recruiting.db")
    rows = conn.execute("SELECT DISTINCT name FROM schools WHERE state=? AND city=? ORDER BY name", (state.upper(), city)).fetchall()
    conn.close()
    return JSONResponse([r[0] for r in rows])
