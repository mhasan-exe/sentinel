import sqlite3
db = sqlite3.connect(input("db name: "))
cur = db.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
print("Tables in the database:")
for row in cur.fetchall():
    print(f" - {row[0]}")
for rows in cur.execute("SELECT name,email,id,password_hash FROM users"):
    print(rows)

