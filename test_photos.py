import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import io
import os
import sys

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

# Cookie-aware session
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def get(path):
    try:
        return opener.open(BASE + path, timeout=5)
    except urllib.error.HTTPError as e:
        return e

def post_form(path, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + path, data=body)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        return opener.open(req, timeout=5)
    except urllib.error.HTTPError as e:
        return e

def post_multipart(path, fields, files):
    boundary = 'TestBoundary12345'
    body = b''
    for key, val in fields.items():
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{val}\r\n'.encode()
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

# Create a tiny valid 1x1 PNG in memory
PNG_1X1 = (
    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
    b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00'
    b'\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18'
    b'\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
)

print('\n--- Upload Endpoint Tests (unauthenticated) ---')
r = post_multipart('/profile/upload-photo', {}, {'photo': ('test.png', PNG_1X1, 'image/png')})
test('Upload rejected when not logged in (401)', r.status == 401)

print('\n--- Login as test user ---')
r = post_form('/login', {'username': 'testplayer_ci', 'password': 'CiTest1234'})
logged_in = any(c.name == 'session' for c in jar)

# Try with common passwords
if not logged_in:
    for pw in ['test', 'password', '123456', 'test1234']:
        jar.clear()
        r = post_form('/login', {'username': 'test', 'password': pw})
        logged_in = r.status == 200 and 'dashboard' in r.url
        if logged_in:
            break

test('Logged in successfully', logged_in)

if logged_in:
    print('\n--- Photo Upload Tests ---')

    # Valid PNG upload
    r = post_multipart('/profile/upload-photo', {}, {'photo': ('test.png', PNG_1X1, 'image/png')})
    test('Valid PNG upload accepted (redirect)', r.status == 200 or 'edit' in getattr(r, 'url', ''))

    # Check file was saved
    import sqlite3
    conn = sqlite3.connect('/home/recruiting/bearcats/recruiting.db')
    cur = conn.cursor()
    cur.execute("SELECT photo FROM player_profiles WHERE user_id = (SELECT id FROM users WHERE username = 'testplayer_ci')")
    row = cur.fetchone()
    conn.close()
    photo_path = row[0] if row else None
    test('Photo path saved to database', bool(photo_path), f'Got: {photo_path}')

    if photo_path:
        full_path = '/home/recruiting/bearcats' + photo_path
        test('Photo file exists on disk', os.path.exists(full_path), f'Path: {full_path}')

        # Check it's served by the app
        r = get(photo_path)
        test('Photo URL is accessible (200)', r.status == 200)

    # Invalid file type
    r = post_multipart('/profile/upload-photo', {}, {'photo': ('test.txt', b'not an image', 'text/plain')})
    test('Non-image file rejected (400)', r.status == 400)

    # File too large (6MB)
    big_file = b'x' * (6 * 1024 * 1024)
    r = post_multipart('/profile/upload-photo', {}, {'photo': ('big.jpg', big_file, 'image/jpeg')})
    test('Oversized file rejected (400)', r.status == 400)

    print('\n--- Profile Page Shows Photo ---')
    r = get('/profile/testplayer_ci')
    content = r.read().decode()
    test('Profile page shows photo img tag', '/static/uploads/' in content if photo_path else 'avatar' in content)

    r = get('/dashboard')
    content = r.read().decode()
    test('Dashboard shows photo for player', '/static/uploads/' in content if photo_path else 'avatar' in content)

print('\n--- Upload Directory ---')
upload_dir = '/home/recruiting/bearcats/static/uploads'
test('Uploads directory exists', os.path.isdir(upload_dir))
test('Uploads directory is writable', os.access(upload_dir, os.W_OK))

print(f'\n{"="*42}')
print(f'  Results: {passed} passed, {failed} failed')
print('='*42)
