import sqlite3
from werkzeug.security import generate_password_hash

# Database connect
conn = sqlite3.connect("users.db")
c = conn.cursor()

# ---------------- CREATE TABLES ----------------
# Users table (password hashed, hidden from admin view)
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')

# Login history table with logout_time column
c.execute('''CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)''')

# ---------------- CREATE DEFAULT ADMIN ----------------
admin_username = "admin"
admin_password = "admin123"
admin_email = "admin@lexpert.com"
hashed_pw = generate_password_hash(admin_password)

# Pehle check karo admin user already exist karta hai ya nahi
c.execute("SELECT * FROM users WHERE username = ?", (admin_username,))
existing_admin = c.fetchone()

if not existing_admin:
    c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
              (admin_username, hashed_pw, admin_email, "admin"))
    print("✅ Default admin account created: username=admin, password=admin123")
else:
    print("ℹ️ Admin user already exists, skipping creation.")

# Save and close
conn.commit()
conn.close()

print("✅ Database initialized successfully with secure password storage!")
