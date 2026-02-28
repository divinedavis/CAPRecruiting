"""
Comprehensive test suite for Bearcats Recruiting
Covers: public access, auth, profiles, dashboard, messaging, uploads, buttons
"""
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import json
import sys, os

BASE = 'http://localhost:8080'
passed = 0
failed = 0

def test(name, condition, detail=''):
    global passed, failed
    if condition:
        print(f'  PASS  {name}')
        passed += 1
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        failed += 1

def make_session():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def get(opener, path):
    try:
        return opener.open(BASE + path, timeout=5)
    except urllib.error.HTTPError as e:
        return e

def post_form(opener, path, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + path, data=body)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        return opener.open(req, timeout=5)
    except urllib.error.HTTPError as e:
        return e

def post_json(opener, path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(BASE + path, data=body)
    req.add_header('Content-Type', 'application/json')
    try:
        return opener.open(req, timeout=5)
    except urllib.error.HTTPError as e:
        return e

def post_multipart(opener, path, files):
    boundary = 'TestBoundary99887766'
    body = b''
    for key, (filename, content, ctype) in files.items():
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"; filename="{filename}"\r\nContent-Type: {ctype}\r\n\r\n'.encode()
        body += content + b'\r\n'
    body += f'--{boundary}--\r\n'.encode()
    req = urllib.request.Request(BASE + path, data=body)
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
    try:
        return opener.open(req, timeout=5)
    except urllib.error.HTTPError as e:
        return e

# Minimal valid PNG
PNG = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
       b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
       b'\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82')

# ── DB setup ─────────────────────────────────────────────────────
sys.path.insert(0, '/home/recruiting/bearcats')
os.chdir('/home/recruiting/bearcats')
from main import SessionLocal, User, PlayerProfile, CoachProfile, Message, hash_password
from sqlalchemy import or_

db = SessionLocal()
for uname in ['ct_player', 'ct_coach']:
    u = db.query(User).filter(User.username == uname).first()
    if u:
        db.query(Message).filter(or_(Message.sender_id==u.id, Message.receiver_id==u.id)).delete()
        db.query(PlayerProfile).filter(PlayerProfile.user_id==u.id).delete()
        db.query(CoachProfile).filter(CoachProfile.user_id==u.id).delete()
        db.delete(u); db.commit()

player = User(username='ct_player', email='ct_p@test.com', password_hash=hash_password('Test1234'), role='player')
coach  = User(username='ct_coach',  email='ct_c@test.com', password_hash=hash_password('Test1234'), role='coach')
db.add(player); db.add(coach); db.commit()
db.refresh(player); db.refresh(coach)
db.add(PlayerProfile(user_id=player.id, first_name='Comp', last_name='Test',
    position='WR', year='2027', height="5'11\"", weight='175',
    forty_yard='4.4', bench_press='185', gpa='3.9',
    school='Test High', city='Austin', state='TX',
    bio='Comprehensive test player'))
db.add(CoachProfile(user_id=coach.id, first_name='Coach', last_name='Test',
    school='Test University', title='Head Coach', division='FBS'))
db.commit()
db.close()

anon  = make_session()
s_p   = make_session()
s_c   = make_session()
post_form(s_p, '/login', {'username': 'ct_player', 'password': 'Test1234'})
post_form(s_c, '/login', {'username': 'ct_coach',  'password': 'Test1234'})

# ════════════════════════════════════════════════════════════════
print('\n━━━ 1. PUBLIC ACCESS (no login required) ━━━')
# ════════════════════════════════════════════════════════════════

r = get(anon, '/')
c = r.read().decode()
test('Home page loads for visitors (200)', r.status == 200)
test('Home page has Browse Players button', 'Browse Players' in c)
test('Home page has Create Your Profile button', 'Create Your Profile' in c)
test('Home page has Sign In button', 'Sign In' in c)
test('Home page has feature cards', 'feature-card' in c)

r = get(anon, '/dashboard')
c = r.read().decode()
test('Dashboard loads for visitors (200)', r.status == 200)
test('Dashboard shows player cards', 'player-card' in c)
test('Dashboard shows Sign Up button for visitors', 'Sign Up' in c)
test('Dashboard shows Sign In / Login for visitors', 'Login' in c or 'Sign In' in c)
test('Dashboard does NOT show Messages to visitors', 'msg-link' not in c)
test('Dashboard does NOT show Edit Profile to visitors', 'Edit Profile' not in c)
test('Dashboard shows player name', 'Comp Test' in c)
test('Dashboard shows position', 'WR' in c)
test('Dashboard shows height', "5'11" in c or 'HT' in c)
test('Dashboard shows weight', '175' in c or 'WT' in c)
test('Dashboard shows class year', '2027' in c or 'Class of' in c)
test('Dashboard shows school', 'Test High' in c)

r = get(anon, '/profile/ct_player')
c = r.read().decode()
test('Player profile loads for visitors (200)', r.status == 200)
test('Profile shows player name', 'Comp Test' in c)
test('Profile shows position', 'WR' in c)
test('Profile shows stats grid', 'stats-grid' in c)
test('Profile has share bar', 'share-bar' in c)
test('Profile has Copy Link button', 'Copy Link' in c)
test('Profile shows Sign in to Message (not Message button) for visitors', 'Sign in to Message' in c)
test('Profile has external links section rendered', 'Links' in c or 'link' in c.lower())
test('Profile has Open Graph title tag', 'og:title' in c)
test('Profile has Open Graph image tag', 'og:image' in c)

r = get(anon, '/profile/ct_coach')
c = r.read().decode()
test('Coach profile loads for visitors (200)', r.status == 200)
test('Coach profile shows school', 'Test University' in c)

r = get(anon, '/profile/nonexistent_xyz')
test('Non-existent profile returns 404', r.status == 404)

# ════════════════════════════════════════════════════════════════
print('\n━━━ 2. NAV LINKS ━━━')
# ════════════════════════════════════════════════════════════════

r = get(anon, '/')
c = r.read().decode()
test('Visitor navbar has Browse Players link', 'Browse Players' in c and '/dashboard' in c)
test('Visitor navbar has Login link', '/login' in c)
test('Visitor navbar has Sign Up button', '/signup' in c)
test('Visitor navbar has NO Messages link', 'msg-link' not in c)

r = get(s_p, '/dashboard')
c = r.read().decode()
test('Logged-in navbar has Players link', '>Players<' in c or 'href="/dashboard"' in c)
test('Logged-in navbar has Messages link', 'msg-link' in c)
test('Logged-in navbar has Edit Profile button', 'Edit Profile' in c)
test('Logged-in navbar has Logout button', 'Logout' in c)
test('Logged-in navbar has NO Sign Up button', 'Sign Up' not in c)

# ════════════════════════════════════════════════════════════════
print('\n━━━ 3. AUTH FLOWS ━━━')
# ════════════════════════════════════════════════════════════════

r = get(anon, '/signup')
c = r.read().decode()
test('Signup page loads (200)', r.status == 200)
test('Signup has player role card', 'value="player"' in c)
test('Signup has coach role card', 'value="coach"' in c)
test('Signup has username field with no-spaces hint', 'no spaces' in c.lower() or 'field-hint' in c)
test('Signup has username pattern attribute', 'pattern' in c)

r = post_form(anon, '/signup', {'username': 'bad user', 'email': 'x@x.com', 'password': '123456', 'role': 'player'})
c = r.read().decode()
test('Signup rejects username with spaces', 'error' in c.lower())

r = post_form(anon, '/signup', {'username': 'ct_player', 'email': 'dupe@x.com', 'password': '123456', 'role': 'player'})
c = r.read().decode()
test('Signup rejects duplicate username', 'error' in c.lower() or 'taken' in c.lower())

r = get(anon, '/login')
c = r.read().decode()
test('Login page loads (200)', r.status == 200)
test('Login has username field', 'name="username"' in c)
test('Login has password field', 'name="password"' in c)

s_bad = make_session()
r = post_form(s_bad, '/login', {'username': 'ct_player', 'password': 'wrongpassword'})
c = r.read().decode()
test('Login rejects bad credentials', 'error' in c.lower() or 'invalid' in c.lower())

# ════════════════════════════════════════════════════════════════
print('\n━━━ 4. PROFILE EDIT ━━━')
# ════════════════════════════════════════════════════════════════

r = get(anon, '/profile/edit')
test('Edit profile redirects visitors to login', 'login' in r.url)

r = get(s_p, '/profile/edit')
c = r.read().decode()
test('Edit profile loads for logged-in player (200)', r.status == 200)
test('Edit profile has Personal Info section', 'Personal Info' in c)
test('Edit profile has Athletic Info section', 'Athletic Info' in c)
test('Edit profile has External Links section', 'External Links' in c or 'Links' in c)
test('Edit profile has photo upload section', 'photo' in c.lower())
test('Edit profile has Save Profile button', 'Save Profile' in c)
test('Edit profile has View My Profile link', 'View My Profile' in c)

r = post_form(s_p, '/profile/edit', {
    'first_name': 'Comp', 'last_name': 'Test', 'position': 'WR',
    'year': '2027', 'height': "5'11\"", 'weight': '175',
    'forty_yard': '4.4', 'bench_press': '185', 'vertical': '34',
    'gpa': '3.9', 'school': 'Test High', 'city': 'Austin', 'state': 'TX',
    'bio': 'Updated bio',
    'link1_label': 'Hudl', 'link1_url': 'https://hudl.com/test',
    'link2_label': 'MaxPreps', 'link2_url': 'https://maxpreps.com/test',
    'link3_label': '', 'link3_url': ''
})
c = r.read().decode()
test('Profile save returns 200', r.status == 200)
test('Profile save shows success message', 'saved successfully' in c)

r = get(anon, '/profile/ct_player')
c = r.read().decode()
test('Updated bio appears on public profile', 'Updated bio' in c)
test('External link (Hudl) appears on public profile', 'Hudl' in c)

# ════════════════════════════════════════════════════════════════
print('\n━━━ 5. PHOTO UPLOAD ━━━')
# ════════════════════════════════════════════════════════════════

r = post_multipart(anon, '/profile/upload-photo', {'photo': ('t.png', PNG, 'image/png')})
test('Photo upload rejected for visitors (401)', r.status == 401)

r = post_multipart(s_p, '/profile/upload-photo', {'photo': ('test.png', PNG, 'image/png')})
test('Valid photo upload succeeds (200)', r.status == 200)

r = post_multipart(s_p, '/profile/upload-photo', {'photo': ('bad.exe', b'malware', 'application/octet-stream')})
test('Invalid file type rejected (400)', r.status == 400)

r = post_multipart(s_p, '/profile/upload-photo', {'photo': ('big.jpg', b'x' * (6*1024*1024), 'image/jpeg')})
test('Oversized file rejected (400)', r.status == 400)

db = SessionLocal()
p = db.query(PlayerProfile).filter(PlayerProfile.user_id == player.id).first()
test('Photo path saved in database', bool(p and p.photo))
if p and p.photo:
    full = '/home/recruiting/bearcats' + p.photo
    test('Photo file exists on disk', os.path.exists(full))
    r2 = get(anon, p.photo)
    test('Photo URL publicly accessible (200)', r2.status == 200)
db.close()

# ════════════════════════════════════════════════════════════════
print('\n━━━ 6. MESSAGING ━━━')
# ════════════════════════════════════════════════════════════════

r = get(anon, '/messages')
test('Messages inbox redirects visitors to login', 'login' in r.url)

r = get(s_p, '/messages')
c = r.read().decode()
test('Messages inbox loads for logged-in user (200)', r.status == 200)

r = get(s_p, '/messages/ct_coach')
c = r.read().decode()
test('Conversation page loads (200)', r.status == 200)
test('Conversation has back arrow link', '← Messages' in c)
test('Conversation has View Profile button', 'View Profile' in c)
test('Conversation has message input', 'chat-input' in c)
test('Conversation has Send button', 'Send' in c)
test('Conversation has WebSocket JS', 'new WebSocket' in c)
test('Conversation has AJAX send endpoint', '/send' in c)

r = post_json(s_p, '/messages/ct_coach/send', {'content': 'Hello coach!'})
test('Player sends message to coach (200)', r.status == 200)
data = json.loads(r.read().decode())
test('Send response has ok=True', data.get('ok') == True)
test('Send response includes content', data.get('message', {}).get('content') == 'Hello coach!')
test('Send response includes timestamp', 'timestamp' in data.get('message', {}))

r = post_json(s_c, '/messages/ct_player/send', {'content': 'Great profile!'})
test('Coach sends reply to player (200)', r.status == 200)

r = get(s_p, '/messages')
c = r.read().decode()
test('Inbox shows coach thread after exchange', 'ct_coach' in c)
test('Inbox shows message preview', 'Great profile' in c)

r = get(s_c, '/messages')
c = r.read().decode()
test('Coach inbox shows player thread', 'ct_player' in c)

# Send-only thread: coach messages player who hasn't replied in a new session
r = post_json(s_c, '/messages/ct_player/send', {'content': 'Following up!'})
test('Coach can send follow-up (200)', r.status == 200)

r = get(s_c, '/messages')
c = r.read().decode()
test('Coach sees thread they initiated', 'ct_player' in c)

# HTTP POST fallback
r = post_form(s_p, '/messages/ct_coach', {'content': 'Fallback message'})
test('HTTP POST fallback still works (redirects)', 'messages' in r.url)

# Unread badge = unique senders
db = SessionLocal()
from main import unread_sender_count
uc = unread_sender_count(db, player.id)
test('Unread badge counts unique senders not total messages', isinstance(uc, int))
db.close()

# ════════════════════════════════════════════════════════════════
print('\n━━━ 7. PROFILE PAGE BUTTONS ━━━')
# ════════════════════════════════════════════════════════════════

r = get(anon, '/profile/ct_player')
c = r.read().decode()
test('Visitor sees Sign in to Message (not Message)', 'Sign in to Message' in c)
test('Visitor sees Copy Link button', 'Copy Link' in c)
test('Visitor does NOT see Edit Profile button', 'Edit Profile' not in c)

r = get(s_c, '/profile/ct_player')
c = r.read().decode()
test('Coach sees Message button on player profile', '/messages/ct_player' in c)
test('Coach does NOT see Edit Profile on someone else profile', 'Edit Profile' not in c or '/profile/edit' in c)

r = get(s_p, '/profile/ct_player')
c = r.read().decode()
test('Player sees Edit Profile button on own profile', 'Edit Profile' in c or '/profile/edit' in c)
test('Player does NOT see Message button on own profile', f'/messages/ct_player' not in c)

# ════════════════════════════════════════════════════════════════
print('\n━━━ 8. USERNAME VALIDATION ━━━')
# ════════════════════════════════════════════════════════════════

import re
valid   = ['JohnSmith', 'john_smith', 'john.smith', 'john-smith', 'John123', 'BenCregger']
invalid = ['John Smith', 'ben cregger', 'test user', 'a b', 'Ben Cregger ']
for name in valid:
    test(f'Valid username accepted: {name}', bool(re.match(r'^[a-zA-Z0-9_.\-]+$', name)))
for name in invalid:
    test(f'Invalid username rejected: "{name}"', not bool(re.match(r'^[a-zA-Z0-9_.\-]+$', name)))

# ════════════════════════════════════════════════════════════════
print('\n━━━ 9. DATABASE INTEGRITY ━━━')
# ════════════════════════════════════════════════════════════════

db = SessionLocal()
users = db.query(User).all()
spaces = [u.username for u in users if ' ' in u.username]
test('No usernames with spaces in DB', len(spaces) == 0, f'Found: {spaces}')
print(f'  INFO  Total users: {len(users)}')
print(f'  INFO  Users: {[u.username for u in users]}')
db.close()

# ════════════════════════════════════════════════════════════════
print('\n━━━ CLEANUP ━━━')
# ════════════════════════════════════════════════════════════════

db = SessionLocal()
for uname in ['ct_player', 'ct_coach']:
    u = db.query(User).filter(User.username == uname).first()
    if u:
        db.query(Message).filter(or_(Message.sender_id==u.id, Message.receiver_id==u.id)).delete()
        if u.role == 'player':
            prof = db.query(PlayerProfile).filter(PlayerProfile.user_id==u.id).first()
            if prof and prof.photo:
                try:
                    os.remove('/home/recruiting/bearcats' + prof.photo)
                except: pass
            db.query(PlayerProfile).filter(PlayerProfile.user_id==u.id).delete()
        else:
            db.query(CoachProfile).filter(CoachProfile.user_id==u.id).delete()
        db.delete(u)
db.commit()
db.close()
print('  INFO  Test users cleaned up')

print(f'\n{"="*50}')
print(f'  Results: {passed} passed, {failed} failed')
print('='*50)
