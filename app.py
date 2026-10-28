"""MockLab — a NISM-style mock-test app with login + free/paid gating.

This is a TEACHING app for your own security practice. It is built the *secure*
way on purpose, so you can test that each protection actually holds. The
companion SECURITY_LAB.md walks you through attacking your own copy and shows
what a broken version would look like.

The three protections a real "live mock" needs, implemented here:
  1. Authentication  — register/login, passwords hashed, server-side session.
  2. Authorization   — paid exams require a paid account ("has this user paid?").
  3. Server-side scoring — the answer key NEVER leaves the server. The browser
                           only ever receives questions + options, never the
                           correct answers. Scoring happens here.

Run:  python app.py   ->  http://127.0.0.1:5000
"""
from __future__ import annotations

import os
import sqlite3
import secrets

from flask import (Flask, g, redirect, render_template, request, session,
                   url_for, abort, flash)
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "mocklab.db")

app = Flask(__name__)
# In real deployment load this from an env var, never hard-code it.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS can't read the session cookie (anti-XSS theft)
    SESSION_COOKIE_SAMESITE="Lax",  # basic CSRF hardening
    # SESSION_COOKIE_SECURE=True,   # turn on when served over HTTPS
)

# ---------------------------------------------------------------------------
# QUESTION BANK — lives on the SERVER. The 'answer' index is never sent to the
# browser. Replace with your own questions. Each exam is free or paid.
# ---------------------------------------------------------------------------
EXAMS = {
    "demo": {
        "title": "Free Demo — Securities Markets Basics",
        "paid": False,
        "questions": [
            {"q": "What does NISM stand for?",
             "options": ["National Institute of Securities Markets",
                         "National Index of Stock Markets",
                         "New Investment & Securities Mission",
                         "National Insurance & Securities Market"],
             "answer": 0,
             "why": "NISM = National Institute of Securities Markets, set up by SEBI."},
            {"q": "Who is the securities market regulator in India?",
             "options": ["RBI", "SEBI", "IRDAI", "PFRDA"],
             "answer": 1,
             "why": "SEBI regulates the securities market in India."},
            {"q": "A 'bull market' refers to a market that is generally…",
             "options": ["Falling", "Flat", "Rising", "Closed"],
             "answer": 2,
             "why": "A bull market trends upward; a bear market trends down."},
        ],
    },
    "mf-v-a": {
        "title": "Series V-A — Mutual Fund Distributors (Full)",
        "paid": True,
        "questions": [
            {"q": "The NAV of a mutual fund scheme is calculated…",
             "options": ["Once a week", "Every business day", "Monthly", "Yearly"],
             "answer": 1,
             "why": "Open-ended scheme NAVs are computed every business day."},
            {"q": "An exit load is charged when an investor…",
             "options": ["Buys units", "Redeems units within a period",
                         "Holds units", "Switches AMC staff"],
             "answer": 1,
             "why": "Exit load applies on redemption within the specified period."},
            {"q": "Which body registers mutual funds in India?",
             "options": ["AMFI", "SEBI", "RBI", "Stock exchange"],
             "answer": 1,
             "why": "Mutual funds are registered with SEBI; AMFI is the industry body."},
        ],
    },
}


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          pw_hash TEXT NOT NULL,
          paid INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS results(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          exam TEXT NOT NULL,
          score INTEGER NOT NULL,
          total INTEGER NOT NULL,
          taken_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """
    )
    db.commit()
    db.close()


def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        if len(u) < 3 or len(p) < 6:
            flash("Username min 3 chars, password min 6 chars.")
            return redirect(url_for("register"))
        db = get_db()
        try:
            # Parameterized query — NOT string concatenation. This is what stops
            # SQL injection. See the lab for the vulnerable version.
            db.execute("INSERT INTO users(username, pw_hash) VALUES(?, ?)",
                       (u, generate_password_hash(p)))
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username already taken.")
            return redirect(url_for("register"))
        flash("Account created. Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        row = get_db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        # check_password_hash compares against the stored hash in constant-ish time
        if row and check_password_hash(row["pw_hash"], p):
            session.clear()
            session["uid"] = row["id"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# For learning only: a button to "pay" so you can test the paid flow without a
# real payment gateway. In production this flips only after a verified payment.
@app.route("/simulate-pay", methods=["POST"])
def simulate_pay():
    user = current_user()
    if not user:
        abort(401)
    db = get_db()
    db.execute("UPDATE users SET paid=1 WHERE id=?", (user["id"],))
    db.commit()
    flash("Payment simulated — you now have paid access.")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# App routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard") if session.get("uid") else url_for("login"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    exams = [{"id": k, "title": v["title"], "paid": v["paid"],
              "n": len(v["questions"])} for k, v in EXAMS.items()]
    results = get_db().execute(
        "SELECT * FROM results WHERE user_id=? ORDER BY id DESC LIMIT 10",
        (user["id"],)).fetchall()
    return render_template("dashboard.html", user=user, exams=exams,
                           results=results)


def can_access(user, exam_id):
    exam = EXAMS.get(exam_id)
    if not exam:
        return None, "not found"
    # AUTHORIZATION CHECK — this is protection #2. A paid exam needs paid=1.
    if exam["paid"] and not user["paid"]:
        return None, "payment required"
    return exam, None


@app.route("/quiz/<exam_id>")
def quiz(exam_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    exam, err = can_access(user, exam_id)
    if err == "not found":
        abort(404)
    if err == "payment required":
        # 402/403 style gate — the quiz is never served without access.
        return render_template("locked.html", exam=EXAMS[exam_id]), 403
    # Build a client-safe copy: questions + options ONLY. No answers, no 'why'.
    safe = [{"q": q["q"], "options": q["options"]} for q in exam["questions"]]
    return render_template("quiz.html", exam_id=exam_id, title=exam["title"],
                           questions=safe)


@app.route("/submit/<exam_id>", methods=["POST"])
def submit(exam_id):
    user = current_user()
    if not user:
        abort(401)
    exam, err = can_access(user, exam_id)   # re-check access on submit too
    if err:
        abort(403)
    # SERVER-SIDE SCORING — protection #3. The browser sent only choices;
    # we compare against the answer key that lives here, never there.
    score = 0
    for i, q in enumerate(exam["questions"]):
        chosen = request.form.get(f"q{i}")
        if chosen is not None and chosen.isdigit() and int(chosen) == q["answer"]:
            score += 1
    total = len(exam["questions"])
    db = get_db()
    cur = db.execute(
        "INSERT INTO results(user_id, exam, score, total) VALUES(?,?,?,?)",
        (user["id"], exam_id, score, total))
    db.commit()
    return redirect(url_for("result", result_id=cur.lastrowid))


@app.route("/result/<int:result_id>")
def result(result_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    row = get_db().execute("SELECT * FROM results WHERE id=?", (result_id,)).fetchone()
    if not row:
        abort(404)
    # IDOR PROTECTION — you may only view YOUR OWN result. Without this check,
    # changing the id in the URL would leak other users' results.
    if row["user_id"] != user["id"]:
        abort(403)
    exam = EXAMS.get(row["exam"], {"title": row["exam"], "questions": []})
    # Now that the attempt is over, it's fine to show the answer key + why.
    review = [{"q": q["q"], "options": q["options"], "answer": q["answer"],
               "why": q["why"]} for q in exam["questions"]]
    return render_template("result.html", row=row, title=exam["title"],
                           review=review)


if __name__ == "__main__":
    init_db()
    print("MockLab running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
