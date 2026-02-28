import urllib.request
import urllib.error
import http.cookiejar

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

def get(path, opener=None):
    try:
        o = opener or urllib.request.build_opener()
        return o.open(BASE + path, timeout=5)
    except urllib.error.HTTPError as e:
        return e

print('\n--- Visitor (no login) Access Tests ---')

r = get('/dashboard')
content = r.read().decode() if r.status == 200 else ''
test('Dashboard loads for visitors (200)', r.status == 200)
test('Dashboard shows Sign Up button for visitors', 'Sign Up' in content)
test('Dashboard shows Sign In button for visitors', 'Sign In' in content)
test('Dashboard shows player grid', 'player-grid' in content or 'player-card' in content or 'No players yet' in content)
test('Dashboard does NOT redirect to login', 'login' not in r.url if hasattr(r, 'url') else True)

r = get('/profile/BenCregger')
test('Player profile visible to visitors (200)', r.status == 200)

r = get('/profile/test')
test('Any profile visible to visitors (200)', r.status == 200)

print('\n--- Player Card Content Tests ---')
r = get('/dashboard')
content = r.read().decode() if r.status == 200 else ''
# Check card shows key stats structure
test('Cards show height label', 'HT' in content or 'height' in content.lower())
test('Cards show weight label', 'WT' in content or 'weight' in content.lower())
test('Cards show class/year label', 'Class of' in content or 'year' in content.lower())
test('Cards show position badge', 'position-badge' in content)
test('Cards show school info', 'player-location' in content)

print(f'\n{"="*42}')
print(f'  Results: {passed} passed, {failed} failed')
print('='*42)
