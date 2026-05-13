import os
import sqlite3
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app import app


def print_schema(db_path: str):
    print(f"DB path: {db_path}")
    print(f"DB exists: {os.path.exists(db_path)}")
    if not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    for table in ["user_profile", "transaction"]:
        try:
            cur.execute(f'PRAGMA table_info("{table}")')
            cols = [r[1] for r in cur.fetchall()]
            print(f"{table} cols: {cols}")
        except Exception as e:
            print(f"{table} PRAGMA error: {e}")
    conn.close()


essential_checks = []

def ok(name, cond):
    essential_checks.append((name, bool(cond)))
    print(f"CHECK: {name}: {'OK' if cond else 'FAIL'}")


def main():
    # Resolve database path (instance-relative SQLite)
    instance_path = app.instance_path
    db_path = os.path.join(instance_path, "fraudguard.db")
    print(f"instance_path: {instance_path}")
    print_schema(db_path)

    # Basic endpoint smoke test using Flask test client
    app.testing = True
    with app.test_client() as client:
        r_root = client.get("/")
        print("GET / ->", r_root.status_code)
        ok("GET / returns 200", r_root.status_code == 200)

        # Try to register a user (idempotent if already exists)
        reg_data = {
            "username": "smokeuser",
            "email": "smoke@example.com",
            "password": "secret123",
            "confirm_password": "secret123",
        }
        r_reg = client.post("/register", data=reg_data, follow_redirects=True)
        print("POST /register ->", r_reg.status_code)
        ok("POST /register returns 200", r_reg.status_code == 200)

        # Login
        r_login = client.post(
            "/login",
            data={"username": "smokeuser", "password": "secret123"},
            follow_redirects=True,
        )
        print("POST /login ->", r_login.status_code)
        ok("POST /login returns 200", r_login.status_code == 200)

        # Dashboard (requires auth)
        r_dash = client.get("/dashboard")
        print("GET /dashboard ->", r_dash.status_code)
        ok("GET /dashboard returns 200", r_dash.status_code == 200)

    all_pass = all(p for _, p in essential_checks)
    print("SUMMARY:")
    for name, passed in essential_checks:
        print(f" - {name}: {'OK' if passed else 'FAIL'}")
    print(f"OVERALL: {'PASS' if all_pass else 'FAIL'}")


if __name__ == "__main__":
    main()
