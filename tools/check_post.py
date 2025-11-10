import sqlite3
import json

db_path = 'tools/callbacks.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check for POST requests
print("=== POST requests in database ===")
posts = cursor.execute("""
    SELECT id, timestamp, method, path, remote_addr, headers, body 
    FROM callbacks 
    WHERE method='POST' 
    ORDER BY id DESC 
    LIMIT 20
""").fetchall()

if posts:
    for row in posts:
        print(f"\nID: {row[0]}")
        print(f"Time: {row[1]}")
        print(f"Method: {row[2]}")
        print(f"Path: {row[3]}")
        print(f"Remote: {row[4]}")
        print(f"Headers: {row[5][:200]}...")
        print(f"Body: {row[6]}")
else:
    print("No POST requests found")

# Check for ANY requests with body containing data
print("\n\n=== Requests with non-empty body ===")
with_body = cursor.execute("""
    SELECT id, timestamp, method, path, remote_addr, body 
    FROM callbacks 
    WHERE body IS NOT NULL AND body != '' 
    ORDER BY id DESC 
    LIMIT 10
""").fetchall()

if with_body:
    for row in with_body:
        print(f"\nID: {row[0]} | {row[1]} | {row[2]} {row[3]} | Remote: {row[4]}")
        print(f"Body: {row[5]}")
else:
    print("No requests with body found")

# Check total count by method
print("\n\n=== Total requests by method ===")
methods = cursor.execute("""
    SELECT method, COUNT(*) as count 
    FROM callbacks 
    GROUP BY method 
    ORDER BY count DESC
""").fetchall()

for method, count in methods:
    print(f"{method}: {count}")

conn.close()
