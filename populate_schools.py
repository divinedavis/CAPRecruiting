import sqlite3, urllib.request, json, time

DB_PATH = "/home/recruiting/bearcats/recruiting.db"
API_BASE = "https://educationdata.urban.org/api/v1/schools/ccd/directory/2022/"

conn = sqlite3.connect(DB_PATH)
conn.execute("""
    CREATE TABLE IF NOT EXISTS schools (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        city TEXT NOT NULL,
        state TEXT NOT NULL
    )
""")
conn.execute("CREATE INDEX IF NOT EXISTS idx_schools_state ON schools(state)")
conn.execute("CREATE INDEX IF NOT EXISTS idx_schools_state_city ON schools(state, city)")
conn.commit()

# Check if already populated
count = conn.execute("SELECT COUNT(*) FROM schools").fetchone()[0]
if count > 1000:
    print(f"Already populated with {count} schools, skipping.")
    conn.close()
    exit()

print("Fetching US high schools from NCES via Urban Institute API...")
url = f"{API_BASE}?per_page=10000&page=1"
inserted = 0
page = 1

while url:
    print(f"  Page {page}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
    except Exception as e:
        print(f"  Error: {e}, retrying in 5s...")
        time.sleep(5)
        continue

    for s in data.get("results", []):
        # Only actual high schools: highest grade must be 12
        if s.get("highest_grade_offered") != 12:
            continue
        name = (s.get("school_name") or "").strip()
        city = (s.get("city_location") or "").strip().title()
        state = (s.get("state_location") or "").strip().upper()
        if name and city and state and len(state) == 2:
            conn.execute("INSERT INTO schools (name, city, state) VALUES (?, ?, ?)", (name, city, state))
            inserted += 1

    conn.commit()
    url = data.get("next")
    page += 1
    time.sleep(0.3)

print(f"Done. Inserted {inserted} high schools.")
conn.close()
