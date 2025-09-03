from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g, flash
import json
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz

app = Flask(__name__)
app.secret_key = "supersecretkey"  # apna secret change kar lena
DATABASE = "users.db"

# ---------------- TIMEZONE HELPER ---------------- #
def get_ist_time():
    """Return current time in Asia/Kolkata timezone (IST)"""
    ist = pytz.timezone("Asia/Kolkata")
    return datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")

# ---------------- DATABASE CONNECTION ---------------- #
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ---------------- LOAD OFFENSE DATA ---------------- #
try:
    with open('offense_data.json', 'r', encoding='utf-8') as file:
        offense_data = json.load(file)
except Exception as e:
    print("Error loading offense_data.json:", e)
    offense_data = []

# ---------------- AUTH ROUTES ---------------- #
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
        hashed_pw = generate_password_hash(password)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, ?)",
                (username, hashed_pw, email, get_ist_time())
            )
            db.commit()
            return redirect(url_for("login"))
        except:
            error = "Username already exists. Please try another."
            return render_template("register.html", error=error)
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            db.execute("INSERT INTO login_history (user_id, login_time) VALUES (?, ?)",
                       (user["id"], get_ist_time()))
            db.commit()
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("index"))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    if "user_id" in session:
        db = get_db()
        db.execute("""
            UPDATE login_history 
            SET logout_time = ? 
            WHERE user_id = ? 
            AND logout_time IS NULL
        """, (get_ist_time(), session["user_id"]))
        db.commit()
    session.clear()
    return redirect(url_for("login"))

# ---------------- ADMIN DASHBOARD ---------------- #
@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        return "❌ Access Denied!"
    db = get_db()
    users = db.execute("SELECT id, username, email, role, created_at FROM users").fetchall()
    history = db.execute("""
        SELECT lh.id, lh.login_time, lh.logout_time, u.username 
        FROM login_history lh 
        JOIN users u ON lh.user_id = u.id 
        ORDER BY lh.login_time DESC
    """).fetchall()
    active_users = sum(1 for h in history if h["logout_time"] is None)
    return render_template("admin.html", users=users, history=history, active_users=active_users)

# ✅ Delete User Route (POST only, JSON response)
@app.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "user_id" not in session or session.get("role") != "admin":
        return jsonify({"success": False, "error": "Access Denied"}), 403
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404
    if user["role"] == "admin":
        return jsonify({"success": False, "error": "Cannot delete admin user"}), 400
    if user_id == session["user_id"]:
        return jsonify({"success": False, "error": "You cannot delete yourself"}), 400
    db.execute("DELETE FROM login_history WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM feedback WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({"success": True})

# --------- New Route: Delete Login History Entry ----------
@app.route("/delete_history/<int:history_id>", methods=["POST"])
def delete_history(history_id):
    if "user_id" not in session or session.get("role") != "admin":
        return jsonify({"success": False, "error": "Access Denied"}), 403
    db = get_db()
    history = db.execute("SELECT * FROM login_history WHERE id = ?", (history_id,)).fetchone()
    if not history:
        return jsonify({"success": False, "error": "Entry not found"}), 404
    db.execute("DELETE FROM login_history WHERE id = ?", (history_id,))
    db.commit()
    return jsonify({"success": True})

# --------- New Route: Delete Feedback Entry ----------
@app.route("/delete_feedback/<int:feedback_id>", methods=["POST"])
def delete_feedback(feedback_id):
    if "user_id" not in session or session.get("role") != "admin":
        return jsonify({"success": False, "error": "Access Denied"}), 403
    db = get_db()
    fb = db.execute("SELECT * FROM feedback WHERE id = ?", (feedback_id,)).fetchone()
    if not fb:
        return jsonify({"success": False, "error": "Feedback not found"}), 404
    db.execute("DELETE FROM feedback WHERE id = ?", (feedback_id,))
    db.commit()
    return jsonify({"success": True})

# ---------------- FEEDBACK ROUTES ---------------- #
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        rating = request.form["rating"]
        review = request.form["review"]
        user_id = session["user_id"]
        db = get_db()
        db.execute("INSERT INTO feedback (user_id, rating, review, created_at) VALUES (?, ?, ?, ?)",
                   (user_id, rating, review, get_ist_time()))
        db.commit()
        return redirect(url_for("thank_you"))
    return render_template("feedback.html", username=session.get("username"), email=session.get("email"))

@app.route("/thank_you")
def thank_you():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("thank_you.html", username=session.get("username"))

@app.route("/admin/feedbacks")
def admin_feedbacks():
    if "user_id" not in session or session.get("role") != "admin":
        return "❌ Access Denied!"
    db = get_db()
    # Sorted offenses alphabetically in admin views not needed here, just return feedbacks as is
    feedbacks = db.execute("""
        SELECT f.id, u.username, u.email, f.rating, f.review, f.created_at
        FROM feedback f
        JOIN users u ON f.user_id = u.id
        ORDER BY f.created_at DESC
    """).fetchall()
    return render_template("admin_feedbacks.html", feedbacks=feedbacks, username=session.get("username"))

# ---------------- ORIGINAL APP ROUTES WITH ALPHABETICAL SORTING ---------------- #
@app.route('/')
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    sorted_offenses = sorted(offense_data, key=lambda o: o['offense'].lower())
    offense_list = [o['offense'] for o in sorted_offenses]
    return render_template('index.html', offense_list=offense_list, username=session.get("username"))

@app.route('/search', methods=['POST'])
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))
    query = request.form.get('query', '').strip().lower()
    results = []
    if query:
        results = [offense for offense in offense_data if query in offense['offense'].lower()]
    return render_template('index.html', results=results, query=query,
                           offense_list=[o['offense'] for o in offense_data], username=session.get("username"))

@app.route('/search_offense')
def search_offense():
    if "user_id" not in session:
        return jsonify([])
    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify([])
    results = [offense for offense in offense_data if query in offense['offense'].lower()]
    return jsonify(results)

@app.route('/directory')
def directory():
    if "user_id" not in session:
        return redirect(url_for("login"))
    sorted_offenses = sorted(offense_data, key=lambda o: o['offense'].lower())
    return render_template('directory.html', offenses=sorted_offenses, username=session.get("username"))

@app.route('/victim', methods=['GET', 'POST'])
def victim():
    if "user_id" not in session:
        return redirect(url_for("login"))
    result = None
    query = None
    sorted_offenses = sorted(offense_data, key=lambda o: o['offense'].lower())
    if request.method == 'POST':
        query = request.form.get('query', '').strip().lower()
    else:
        query = request.args.get('query', '').strip().lower()
    if query:
        for offense in sorted_offenses:
            if query == offense['offense'].lower() or query == offense['section'].lower():
                result = offense
                break
    return render_template('victim.html', result=result,
                           offense_list=[o['offense'] for o in sorted_offenses], username=session.get("username"))

@app.route('/about')
def about():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template('about.html', username=session.get("username"))

@app.route('/notes')
def notes():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template('notes.html', offense_data=offense_data, username=session.get("username"))

# ---------------- RUN APP ---------------- #
if __name__ == '__main__':
    app.run(debug=True)
