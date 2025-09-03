import sqlite3
from datetime import datetime
import pytz

# Setup timezone
utc = pytz.utc
ist = pytz.timezone("Asia/Kolkata")

def convert_to_ist(utc_time_str):
    """Convert UTC timestamp string to IST formatted string"""
    if not utc_time_str:
        return "-"
    try:
        # Parse string into datetime (assuming stored as "YYYY-MM-DD HH:MM:SS")
        dt_utc = datetime.strptime(utc_time_str, "%Y-%m-%d %H:%M:%S")
        dt_utc = dt_utc.replace(tzinfo=utc)  # set as UTC
        dt_ist = dt_utc.astimezone(ist)      # convert to IST
        return dt_ist.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return utc_time_str  # fallback: return as-is if parsing fails


# Connect to database
conn = sqlite3.connect("users.db")
c = conn.cursor()

# ===== Users Table =====
print("===== Users Table =====")
print("{:<5} {:<15} {:<25} {:<10} {:<25}".format(
    "ID", "Username", "Email", "Role", "Created At (IST)"
))
print("-" * 90)

for row in c.execute("SELECT id, username, email, role, created_at FROM users"):
    created_at_ist = convert_to_ist(row[4])
    print("{:<5} {:<15} {:<25} {:<10} {:<25}".format(
        row[0], row[1], row[2] or "-", row[3], created_at_ist
    ))

# ===== Login History =====
print("\n===== Login History =====")
print("{:<5} {:<10} {:<25} {:<25}".format(
    "ID", "UserID", "Login Time (IST)", "Logout Time (IST)"
))
print("-" * 75)

for row in c.execute("SELECT id, user_id, login_time, logout_time FROM login_history"):
    login_ist = convert_to_ist(row[2])
    logout_ist = convert_to_ist(row[3])
    print("{:<5} {:<10} {:<25} {:<25}".format(
        row[0], row[1], login_ist, logout_ist
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
