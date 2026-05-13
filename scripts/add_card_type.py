import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "instance" / "fraudguard.db"
print(f"Using DB: {DB_PATH}")
conn = sqlite3.connect(str(DB_PATH))
cur = conn.cursor()

# Show current columns
cur.execute('PRAGMA table_info("transaction")')
print('Before cols:', [r[1] for r in cur.fetchall()])

# Try adding the column with different quoting styles
added = False
for stmt in [
    'ALTER TABLE "transaction" ADD COLUMN card_type VARCHAR(20)',
    'ALTER TABLE [transaction] ADD COLUMN card_type VARCHAR(20)',
    'ALTER TABLE `transaction` ADD COLUMN card_type VARCHAR(20)'
]:
    try:
        cur.execute(stmt)
        print('Executed:', stmt)
        added = True
        break
    except Exception as e:
        print('Failed:', stmt, '->', e)

if added:
    conn.commit()
    cur.execute('PRAGMA table_info("transaction")')
    print('After cols:', [r[1] for r in cur.fetchall()])
else:
    print('Could not add card_type column by any method')

conn.close()
