from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g
import json
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"  # apna secret change kar lena

DATABASE = "users.db"

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
            db.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                       (username, hashed_pw, email))
            db.commit()
            return redirect(url_for("login"))
        except:
            # ❌ username duplicate error
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

            # save login history
            db.execute("INSERT INTO login_history (user_id, login_time) VALUES (?, ?)",
                       (user["id"], datetime.now()))
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
        # last login record ka logout_time update karo
        db.execute("""
            UPDATE login_history 
            SET logout_time = ? 
            WHERE user_id = ? 
            AND logout_time IS NULL
        """, (datetime.now(), session["user_id"]))
        db.commit()

    session.clear()
    return redirect(url_for("login"))

# ---------------- ADMIN DASHBOARD ---------------- #
@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        return "❌ Access Denied!"

    db = get_db()
    # ❌ password field intentionally exclude
    users = db.execute("SELECT id, username, email, role, created_at FROM users").fetchall()
    history = db.execute("""
        SELECT lh.login_time, lh.logout_time, u.username 
        FROM login_history lh 
        JOIN users u ON lh.user_id = u.id 
        ORDER BY lh.login_time DESC
    """).fetchall()

    return render_template("admin.html", users=users, history=history)

# ---------------- ORIGINAL APP ROUTES ---------------- #
@app.route('/')
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    offense_list = [o['offense'] for o in offense_data]
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

    return render_template('directory.html', offenses=offense_data, username=session.get("username"))

@app.route('/victim', methods=['GET', 'POST'])
def victim():
    if "user_id" not in session:
        return redirect(url_for("login"))

    result = None
    query = None
    
    if request.method == 'POST':
        query = request.form.get('query', '').strip().lower()
    else:
        query = request.args.get('query', '').strip().lower()

    if query:
        for offense in offense_data:
            if query == offense['offense'].lower() or query == offense['section'].lower():
                result = offense
                break

    return render_template('victim.html', result=result,
                           offense_list=[o['offense'] for o in offense_data], username=session.get("username"))

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
