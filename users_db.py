import sqlite3

# Connect to database
conn = sqlite3.connect("users.db")
c = conn.cursor()

# ===== Users Table =====
print("===== Users Table =====")
print("{:<5} {:<15} {:<25} {:<10} {:<25}".format(
    "ID", "Username", "Email", "Role", "Created At"
))
print("-" * 90)

for row in c.execute("SELECT id, username, email, role, created_at FROM users"):
    print("{:<5} {:<15} {:<25} {:<10} {:<25}".format(
        row[0], row[1], row[2] or "-", row[3], row[4]
    ))

# ===== Login History =====
print("\n===== Login History =====")
print("{:<5} {:<10} {:<25} {:<25}".format(
    "ID", "UserID", "Login Time", "Logout Time"
))
print("-" * 75)

for row in c.execute("SELECT id, user_id, login_time, logout_time FROM login_history"):
    print("{:<5} {:<10} {:<25} {:<25}".format(
        row[0], row[1], row[2], row[3] if row[3] else "-"
    ))

# ===== Currently Logged In Users =====
print("\n===== Currently Logged In Users =====")
print("{:<5} {:<15} {:<25} {:<10}".format(
    "ID", "Username", "Email", "Role"
))
print("-" * 60)

for row in c.execute("""
    SELECT u.id, u.username, u.email, u.role
    FROM users u
    JOIN login_history lh ON u.id = lh.user_id
    WHERE lh.logout_time IS NULL
"""):
    print("{:<5} {:<15} {:<25} {:<10}".format(
        row[0], row[1], row[2] or "-", row[3]
    ))

# Close connection
conn.close()
