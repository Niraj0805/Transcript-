# MockLab — a mock-test app you can secure and attack (your own)

A small NISM-style mock-test web app with **login**, **free vs paid exams**, and
**server-side scoring** — plus a hands-on **security lab** that teaches you to
test and break it. All on your own machine.

## What it demonstrates

The three protections a real "live mock test" needs:

1. **Authentication** — register / log in; passwords hashed; server-side session.
2. **Authorization** — paid exams require a paid account, checked on every
   endpoint (page *and* submit).
3. **Server-side scoring** — the answer key never reaches the browser; the server
   scores your choices. Nothing to cheat from "View Source".

## Run it

Use **Python 3.11 or 3.12** (smoothest), then:

```
cd mocklab
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**, register an account, and try the free demo. To
try a paid exam, click **Simulate payment** on the dashboard (stands in for a
real payment gateway), then open the paid exam.

## Learn to break it

Open **SECURITY_LAB.md** and work through the exercises — broken access control,
IDOR, client-side answer leakage, auth/session checks, and SQL injection. Each
one shows the attack (run it with `curl`), the vulnerable code, and the fix.

## Files

```
app.py              Flask app: auth, gating, server-side scoring, results
templates/          login, register, dashboard, quiz, locked, result
SECURITY_LAB.md     the hands-on security exercises
requirements.txt    dependencies (Flask)
mocklab.db          created on first run (SQLite; delete to reset)
```

## Make it yours

- Replace the questions in `EXAMS` at the top of `app.py` with your own.
- Swap **Simulate payment** for a real gateway (Razorpay/Stripe), flipping
  `paid=1` only after a verified payment webhook.
- Add rate-limiting on `/login` (an exercise in the lab).

## Rules of the road

The security techniques in the lab are for **your own app** (or systems you're
explicitly authorized to test). Don't point them at anyone else's site.
