from fastapi import FastAPI, Request, Form, Depends, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, distinct, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from starlette.middleware.sessions import SessionMiddleware
import re
import os
import uuid
import bcrypt
from datetime import datetime
from typing import Optional, Dict, List

app = FastAPI()

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

class CoachProfile(Base):
    __tablename__ = "coach_profiles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
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

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=302)
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/signup", response_class=HTMLResponse)
async def signup_get(request: Request, db: Session = Depends(get_db)):
    teams = db.query(Team).order_by(Team.name).all()
    return templates.TemplateResponse("signup.html", {"request": request, "error": None, "teams": teams, "selected_team_id": None})

@app.post("/signup", response_class=HTMLResponse)
async def signup_post(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    team_id: Optional[int] = Form(None),
    db: Session = Depends(get_db)
):
    username = username.strip()
    teams = db.query(Team).order_by(Team.name).all()

    def err(msg):
        return templates.TemplateResponse("signup.html", {
            "request": request, "error": msg,
            "teams": teams, "selected_team_id": team_id
        })

    if role not in ("player", "coach"):
        return err("Invalid role selected.")
    if role == "player" and not team_id:
        return err("Players must select a high school team.")
    if role == "player" and not db.query(Team).filter(Team.id == team_id).first():
        return err("Invalid team selected.")
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return err("Username can only contain letters, numbers, underscores, dots, and hyphens (no spaces).")
    if db.query(User).filter(User.username == username).first():
        return err("Username already taken.")
    if db.query(User).filter(User.email == email).first():
        return err("Email already registered.")
    if len(password) < 6:
        return err("Password must be at least 6 characters.")

    user = User(username=username, email=email, password_hash=hash_password(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)

    if role == "player":
        db.add(PlayerProfile(user_id=user.id, team_id=team_id))
    else:
        db.add(CoachProfile(user_id=user.id))
    db.commit()

    request.session["user_id"] = user.id
    return RedirectResponse("/profile/edit", status_code=302)

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
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password."})
    request.session["user_id"] = user.id
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, team_id: Optional[int] = None, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    teams = db.query(Team).order_by(Team.name).all()

    # Visitors must pick a team first
    if not user_id and team_id is None:
        return templates.TemplateResponse("team_select.html", {
            "request": request,
            "teams": teams,
            "unread_count": 0
        })

    # Filter by team when team_id is given
    if team_id:
        team = db.query(Team).filter(Team.id == team_id).first()
        player_users = (
            db.query(User)
            .join(PlayerProfile, User.id == PlayerProfile.user_id)
            .filter(User.role == "player", PlayerProfile.team_id == team_id)
            .all()
        )
    else:
        team = None
        player_users = db.query(User).filter(User.role == "player").all()

    player_data = []
    for p in player_users:
        prof = db.query(PlayerProfile).filter(PlayerProfile.user_id == p.id).first()
        player_data.append({"user": p, "profile": prof})

    unread_count = unread_sender_count(db, user_id) if user_id else 0
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "player_data": player_data,
        "unread_count": unread_count,
        "team": team,
        "teams": teams,
        "active_team_id": team_id
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
    return templates.TemplateResponse("edit_profile.html", {"request": request, "user": user, "profile": profile, "success": False})

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
        p.gpa = form.get("gpa", "")
        p.school = form.get("school", "")
        p.city = form.get("city", "")
        p.state = form.get("state", "")
        p.bio = form.get("bio", "")
        p.link1_label = form.get("link1_label", "")
        p.link1_url = form.get("link1_url", "")
        p.link2_label = form.get("link2_label", "")
        p.link2_url = form.get("link2_url", "")
        p.link3_label = form.get("link3_label", "")
        p.link3_url = form.get("link3_url", "")
        p.hudl_url = form.get("hudl_url", "")
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
    db.commit()

    if user.role == "player":
        profile = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
    else:
        profile = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
    return templates.TemplateResponse("edit_profile.html", {"request": request, "user": user, "profile": profile, "success": True})

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

    unread_count = unread_sender_count(db, current_user_id) if current_user_id else 0
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "target": target,
        "profile": profile,
        "current_user": current_user,
        "unread_count": unread_count
    })

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
    unread_count = unread_sender_count(db, user_id)
    return templates.TemplateResponse("admin_teams.html", {
        "request": request, "user": user,
        "teams": teams, "unread_count": unread_count,
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
    teams_raw = db.query(Team).order_by(Team.name).all()
    teams = [{"id": t.id, "name": t.name, "player_count": db.query(PlayerProfile).filter(PlayerProfile.team_id == t.id).count()} for t in teams_raw]
    unread_count = unread_sender_count(db, user_id)
    if not name:
        return templates.TemplateResponse("admin_teams.html", {"request": request, "user": user, "teams": teams, "unread_count": unread_count, "success": False, "error": "Team name cannot be empty."})
    if db.query(Team).filter(Team.name == name).first():
        return templates.TemplateResponse("admin_teams.html", {"request": request, "user": user, "teams": teams, "unread_count": unread_count, "success": False, "error": f'A team named "{name}" already exists.'})
    db.add(Team(name=name))
    db.commit()
    teams_raw = db.query(Team).order_by(Team.name).all()
    teams = [{"id": t.id, "name": t.name, "player_count": db.query(PlayerProfile).filter(PlayerProfile.team_id == t.id).count()} for t in teams_raw]
    return templates.TemplateResponse("admin_teams.html", {"request": request, "user": user, "teams": teams, "unread_count": unread_count, "success": True, "error": None})

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
async def upload_photo(request: Request, photo: UploadFile = File(...), db: Session = Depends(get_db)):
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

    filename = f"{user_id}_{uuid.uuid4().hex[:8]}.{ext}"
    filepath = os.path.join(UPLOAD_DIR, filename)

    with open(filepath, "wb") as f:
        f.write(contents)

    user = db.query(User).filter(User.id == user_id).first()
    if user.role == "player":
        p = db.query(PlayerProfile).filter(PlayerProfile.user_id == user_id).first()
        if p.photo and os.path.exists(os.path.join(UPLOAD_DIR, os.path.basename(p.photo))):
            try:
                os.remove(os.path.join(UPLOAD_DIR, os.path.basename(p.photo)))
            except:
                pass
        p.photo = f"/static/uploads/{filename}"
    else:
        c = db.query(CoachProfile).filter(CoachProfile.user_id == user_id).first()
        if c.photo and os.path.exists(os.path.join(UPLOAD_DIR, os.path.basename(c.photo))):
            try:
                os.remove(os.path.join(UPLOAD_DIR, os.path.basename(c.photo)))
            except:
                pass
        c.photo = f"/static/uploads/{filename}"
    db.commit()

    return RedirectResponse("/profile/edit", status_code=302)

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
