import sqlite3
from pathlib import Path
import json

db = Path(__file__).parent / 'callbacks.db'
print('DB path:', db)
if not db.exists():
    print('DB not found')
    raise SystemExit(0)
conn = sqlite3.connect(db)
cur = conn.cursor()
rows = cur.execute("SELECT id,timestamp,method,path,remote_addr,user_agent FROM callbacks ORDER BY id DESC LIMIT 10").fetchall()
print(json.dumps(rows, default=str, indent=2))
conn.close()
