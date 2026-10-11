"""SafeSense: Flask web app.   Run:  python app.py   then open http://127.0.0.1:5000"""
import os

from flask import Flask, jsonify, render_template, request

from safesense.engine import scan

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # reject very large uploads

SAMPLES = {
    "phishing": (
        'From: "PayPal Support" <service@paypa1-secure.example.com>\n'
        "Reply-To: help@mail-collector.example.net\n"
        "Subject: Security alert: your account will be suspended\n\n"
        "Dear customer,\n\n"
        "We noticed unusual activity on your account. Your account will be suspended within 24 hours "
        "unless you verify your identity immediately.\n\n"
        '<a href="http://paypa1-secure.example.com/verify/login?id=88213">https://www.paypal.com/verify</a>\n\n'
        "Please enter your password and card number to restore access.\n\nPayPal Security Team"
    ),
    "prize": (
        "Congratulations! You have won KES 250,000 in the M-PESA customer draw.\n\n"
        "To claim your prize, send your ID number and PIN to confirm your identity, "
        "then open: http://bit.ly/claim-mpesa-prize\n\nOffer expires today. Act now!"
    ),
    "legit": (
        "From: Amina Wanjiru <amina@brightleaf-consulting.example.com>\n"
        "Subject: Notes from Tuesday and next call\n\n"
        "Hi, thanks for joining the call on Tuesday. I have put the meeting notes in our shared folder. "
        "Could we speak again on Thursday at 10:00 to go over the spreadsheet?\n\n"
        "https://meet.google.com/abc-defg-hij\n\nKind regards,\nAmina"
    ),
}


@app.get("/")
def index():
    return render_template("index.html", samples=SAMPLES)


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", ""))[:50_000]
    if not text.strip():
        return jsonify(error="Please paste a message or link to check."), 400
    return jsonify(scan(text))


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
