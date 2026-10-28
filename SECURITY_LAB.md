# MockLab Security Lab — learn to break (and fix) your own app

This teaches you to **test the security of your own mock-test app**. Everything
here runs against *your own copy* on `localhost`. That's the golden rule: these
techniques are for systems you own or are authorized to test — never anyone
else's.

The app is built the *secure* way, so each exercise shows you two things:
1. **The attack** — how someone would probe for the weakness (run it yourself).
2. **The broken vs fixed code** — what makes the app vulnerable, and the line
   that stops it.

## Setup

```
cd mocklab
pip install -r requirements.txt
python app.py              # http://127.0.0.1:5000
```

Register two accounts in the browser: `alice` (stays free) and `mallory`
(you'll make her "pay"). Then open a terminal for the attacks. Save each user's
cookies so curl acts "as" them:

```
# log in and keep the session cookie
curl -s -c alice.txt -d "username=alice&password=secret123" http://127.0.0.1:5000/login
curl -s -c mal.txt   -d "username=mallory&password=secret123" http://127.0.0.1:5000/login
```

---

## 1. Broken Access Control  (the #1 web vulnerability)

**The idea:** a free user should not reach a paid exam. The *page* hides the
link — but attackers don't use the page, they hit the URL directly.

**Attack — request the paid exam as a free user:**
```
curl -s -b alice.txt http://127.0.0.1:5000/quiz/mf-v-a -o out.html -w "%{http_code}\n"
```
Secure result: **403**, and `out.html` is the "locked" page — no questions.

**What a BROKEN version looks like** (don't ship this):
```python
@app.route("/quiz/<exam_id>")
def quiz(exam_id):
    exam = EXAMS[exam_id]                 # ❌ no "has this user paid?" check
    return render_template("quiz.html", ...)   # paid questions served to anyone
```
**The fix** (what this app does) is the `can_access()` check before serving, and
**again inside `/submit`** — because a clever user will skip the page and POST
straight to the scoring endpoint:
```
curl -s -b alice.txt -X POST -d "q0=0" http://127.0.0.1:5000/submit/mf-v-a -w "%{http_code}\n"
```
Secure result: **403**. Lesson: **check authorization on every endpoint that
touches protected data, not just the one that renders the page.**

---

## 2. IDOR — Insecure Direct Object Reference

**The idea:** results are at `/result/<id>`. If the server doesn't check *who
owns* that result, you can read other people's by changing the number.

**Attack — alice takes the demo, mallory tries to read alice's result:**
```
# alice submits, note the result id in the redirect URL (e.g. /result/2)
curl -s -b alice.txt -X POST -d "q0=0&q1=1&q2=1" http://127.0.0.1:5000/submit/demo -o /dev/null -w "%{redirect_url}\n"
# mallory tries that id
curl -s -b mal.txt http://127.0.0.1:5000/result/2 -w "  %{http_code}\n" -o /dev/null
```
Secure result: **403** for mallory, **200** for alice.

**Broken vs fixed:**
```python
row = db.execute("SELECT * FROM results WHERE id=?", (result_id,)).fetchone()
# ❌ broken: return it to anyone who knows the id
# ✅ fixed:
if row["user_id"] != current_user_id:
    abort(403)
```
Lesson: **owning the id is not the same as owning the data. Always check the
record belongs to the requester.**

---

## 3. Client-side answer leakage

**The idea:** if the browser ever receives the answer key, the quiz is pointless
— anyone can read it in "View Source" or the Network tab.

**Attack — look for the answers in what the server sent:**
```
curl -s -b alice.txt http://127.0.0.1:5000/quiz/demo | grep -iE "correct|answer\":|\"why\""
```
Secure result: nothing but the UI text "Answer all questions" — the correct-
option index and explanations are **not** in the page. (In a browser: open
DevTools → Network → the quiz request → Response, and confirm the same.)

**What a BROKEN version looks like:** sending the full question objects to the
browser and scoring in JavaScript:
```js
// ❌ the answer key is now in the page source
const QUESTIONS = [{q:"...", options:[...], answer:0}];
if (chosen === QUESTIONS[i].answer) score++;   // trivially cheatable
```
**The fix** (this app): the server builds a *client-safe* copy with questions +
options only, and scores in `/submit` against the key that never left the
server. Lesson: **trust nothing the client sends; keep the source of truth —
and the answer key — on the server.**

---

## 4. Authentication & sessions

Things to verify on your own app:

- **Passwords are hashed, never stored plaintext.** Open `mocklab.db`:
  ```
  python -c "import sqlite3;print(sqlite3.connect('mocklab.db').execute('select username,pw_hash from users').fetchall())"
  ```
  You'll see `scrypt:...` hashes, not the passwords. ❌ Broken = storing `password`
  as-is. ✅ Fixed = `generate_password_hash` / `check_password_hash`.
- **Session cookie flags.** This app sets `HttpOnly` (JavaScript can't read the
  cookie, blunting XSS theft) and `SameSite=Lax` (basic CSRF defense). Add
  `SESSION_COOKIE_SECURE=True` once you serve over HTTPS. Check with:
  ```
  curl -s -i -d "username=alice&password=secret123" http://127.0.0.1:5000/login | grep -i set-cookie
  ```
- **Brute force.** Try logging in with many wrong passwords — it never locks out
  here. Real apps add rate-limiting / lockout / CAPTCHA. That's your next
  exercise: add a counter and block after N failures.

---

## 5. SQL injection

This app uses **parameterized queries** everywhere (`execute("… WHERE username=?", (u,))`),
which is immune to injection. To understand *why*, here's the dangerous pattern
and how you'd test it:

```python
# ❌ NEVER do this — user input glued straight into SQL
db.execute("SELECT * FROM users WHERE username='" + u + "'")
```
With that broken code, a username like `' OR '1'='1` changes the query's meaning.
Test your own login field with inputs like:
```
' OR '1'='1
admin'--
```
On this app: they just fail as invalid logins (the `?` placeholder treats them as
plain text). Lesson: **never build SQL by string concatenation; always use
placeholders.**

---

## The attacker mindset (the real takeaway)

Every bug above comes from one habit: **trusting the client.** The browser is
fully under the user's control — URLs, form fields, cookies, and JavaScript can
all be changed. So the server must independently:

- **authenticate** (who are you),
- **authorize** (are you allowed *this* thing),
- **validate** (is this input sane),
- and keep **secrets and scoring** on its side.

Good tools to go further on your own app: browser **DevTools** (Network/Console),
`curl` (what you used here), and **OWASP ZAP** or **Burp Suite** (intercept and
replay requests). Work through the **OWASP Top 10** — it's the canonical list,
and you've just done #1 (Access Control), its IDOR cousin, and touched auth and
injection.

**Only ever run these against your own apps or ones you're explicitly authorized
to test.**
