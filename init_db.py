import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "users.db"

def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    return any(col[1] == column for col in cursor.fetchall())

def table_exists(cursor, table):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table,))
    return cursor.fetchone() is not None

def ensure_users_table(cursor):
    # Base table (already exists in current DB); create if missing
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Add dob column if not present (TEXT, store as YYYY-MM-DD)
    if not column_exists(cursor, "users", "dob"):
        cursor.execute("ALTER TABLE users ADD COLUMN dob TEXT")

def ensure_login_history_table(cursor):
    cursor.execute('''CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        logout_time TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

def ensure_feedback_table(cursor):
    cursor.execute('''CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        rating INTEGER,
        review TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

def ensure_password_updates_table(cursor):
    # New table to log password resets/updates
    cursor.execute('''CREATE TABLE IF NOT EXISTS password_updates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        method TEXT DEFAULT 'forgot_flow',
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

def ensure_default_admin(cursor):
    admin_username = "admin"
    admin_password = "admin123"
    admin_email = "admin@lexpert.com"
    hashed_pw = generate_password_hash(admin_password)

    cursor.execute("SELECT 1 FROM users WHERE username = ?", (admin_username,))
    if cursor.fetchone() is None:
        cursor.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            (admin_username, hashed_pw, admin_email, "admin")
        )
        print("✅ Default admin account created: username=admin, password=admin123")
    else:
        print("ℹ️ Admin user already exists, skipping creation.")

def main():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Ensure all tables/columns exist
    ensure_users_table(c)                 # adds users (if missing) + dob column migration
    ensure_login_history_table(c)         # unchanged
    ensure_feedback_table(c)              # unchanged
    ensure_password_updates_table(c)      # NEW for logging password changes

    # Seed default admin (idempotent)
    ensure_default_admin(c)

    conn.commit()
    conn.close()
    print("✅ Database initialized: users(dob), login_history, feedback, password_updates ready.")

if __name__ == "__main__":
    main()
