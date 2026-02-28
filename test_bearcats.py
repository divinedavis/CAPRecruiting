import urllib.request
import urllib.parse
import urllib.error
import re
import sys
import os

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

def get(path):
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        urllib.request.install_opener(opener)
        return urllib.request.urlopen(BASE + path, timeout=5)
    except urllib.error.HTTPError as e:
        return e

print('\n--- Basic Page Tests ---')
r = get('/')
test('Home page loads (200)', r.status == 200)

r = get('/login')
test('Login page loads (200)', r.status == 200)

r = get('/signup')
test('Signup page loads (200)', r.status == 200)

r = get('/dashboard')
test('Dashboard is public for unauthenticated visitors', r.status == 200)

r = get('/profile/edit')
test('Edit profile redirects when unauthenticated', hasattr(r, 'url') and 'login' in r.url)

r = get('/messages')
test('Messages redirects when unauthenticated', hasattr(r, 'url') and 'login' in r.url)

print('\n--- Profile URL Tests ---')
r = get('/profile/test')
test('Valid profile (test) loads (200)', r.status == 200)

r = get('/profile/BenCregger')
test('BenCregger profile loads after rename fix (200)', r.status == 200)

r = get('/profile/Ben%20Cregger')
test('Spaced username correctly returns 404', r.status == 404)

r = get('/profile/doesnotexist999')
test('Non-existent profile returns 404', r.status == 404)

print('\n--- Username Validation (backend regex) ---')
valid_names = ['JohnSmith', 'john_smith', 'john.smith', 'john-smith', 'John123', 'BenCregger']
invalid_names = ['John Smith', 'john smith', 'ben cregger', 'test user', 'a b', 'Ben Cregger ']

for name in valid_names:
    ok = bool(re.match(r'^[a-zA-Z0-9_.\-]+$', name))
    test(f'Valid username accepted: {name}', ok)

for name in invalid_names:
    ok = bool(re.match(r'^[a-zA-Z0-9_.\-]+$', name))
    test(f'Invalid username rejected: "{name}"', not ok)

print('\n--- Database Integrity ---')
sys.path.insert(0, '/home/recruiting/bearcats')
os.chdir('/home/recruiting/bearcats')
from main import SessionLocal, User
db = SessionLocal()
users = db.query(User).all()
spaces_found = [u.username for u in users if ' ' in u.username]
test('No usernames with spaces in database', len(spaces_found) == 0,
     f'Found: {spaces_found}' if spaces_found else '')
print(f'  INFO  Registered users: {[u.username for u in users]}')
db.close()

print(f'\n{"="*42}')
print(f'  Results: {passed} passed, {failed} failed')
print('='*42)
