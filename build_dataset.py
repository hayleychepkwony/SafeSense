"""Builds data/messages.csv: a labelled sample dataset of phishing and legitimate messages.

Messages are assembled from many varied templates (with a fixed random seed so
the file is reproducible). Run:  python data/build_dataset.py
"""
import csv
import os
import random

random.seed(7)

NAMES = ["Amina", "Brian", "Cynthia", "David", "Esther", "Felix", "Grace", "Hassan", "Irene", "James", "Kevin", "Lucy"]
BRANDS = ["PayPal", "Microsoft", "Google", "Apple", "Amazon", "Netflix", "DHL", "Safaricom", "LinkedIn", "Dropbox", "DocuSign", "your bank"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
TIMES = ["9:00", "10:30", "11:00", "14:00", "15:30", "16:00"]
TOPICS = ["the budget spreadsheet", "the project timeline", "the client proposal", "the onboarding checklist",
          "the quarterly report", "the website copy", "the travel plan", "the training schedule"]

# ----- phishing building blocks -------------------------------------------
P_OPEN = [
    "Dear customer,", "Dear user,", "Dear account holder,", "Attention:", "SECURITY ALERT:", "Hello,", "Notice:",
    "Valued member,", "URGENT:", "Final notice:", "Important:",
]
P_REASON = [
    "We detected unusual activity on your {b} account.",
    "Your {b} account has been locked due to suspicious login attempts.",
    "Your {b} account will be suspended within 24 hours.",
    "We were unable to verify your billing information.",
    "Your password has expired and must be updated now.",
    "A payment of $499.00 was made from your account. If this was not you, act immediately.",
    "Your mailbox storage is full and incoming messages will be rejected.",
    "A package could not be delivered because an address detail is missing.",
    "Your {b} subscription payment failed and your service will be cancelled.",
    "Someone tried to sign in to your {b} account from a new device.",
    "You have been selected to receive a refund of KES 12,500.",
    "Congratulations, you have won a prize in the {b} customer draw.",
    "Your tax refund is pending and requires confirmation of your details.",
    "Your account has been compromised and needs immediate verification.",
    "We need to confirm your identity to keep your account active.",
]
P_ACTION = [
    "Verify your account now", "Confirm your password immediately", "Click the link below to restore access",
    "Log in to confirm your identity", "Update your payment details within 24 hours",
    "Reply with your PIN and ID number to claim your prize", "Enter your card number and CVV to continue",
    "Sign in to cancel the transaction", "Download the attached invoice and enable macros",
    "Pay the small redelivery fee to release your parcel", "Share the one-time password sent to your phone",
    "Open the secure document and sign in with your email password",
]
P_LINK = [
    "http://{d}/verify/login", "https://{d}/secure/update", "http://bit.ly/{x}", "https://tinyurl.com/{x}",
    "http://203.0.113.{n}/account", "https://{d}/signin?ref={x}", "http://{d}/confirm",
]
P_DOM = ["paypa1-secure.example.com", "micros0ft-support.example.net", "account-verify.example.org",
         "secure-login-update.example.com", "netfIix-billing.example.net", "apple-id-locked.example.org",
         "dhl-parcel-fee.example.com", "mpesa-prize.example.net"]
P_CLOSE = [
    "Failure to respond will result in permanent closure.", "This is your last warning.",
    "Act now to avoid losing access.", "Thank you for your immediate attention.",
    "Security Team", "Customer Support", "This offer expires today.", "",
]

# ----- legitimate building blocks -----------------------------------------
L_MSG = [
    "Hi {n}, thanks for the call on {d}. I have added the notes for {t} to our shared folder. Can we speak again at {tm}?",
    "Hello team, reminder that our weekly meeting is on {d} at {tm}. Please review {t} beforehand.",
    "Hi {n}, attached is {t} as discussed. Let me know if anything needs changing and I will update it today.",
    "Good morning, I have finished {t}. Could you take a look when you have a moment? No rush, end of week is fine.",
    "Hi {n}, just checking in on {t}. Happy to jump on a quick call {d} if that helps.",
    "Thank you for your order. Your receipt is attached and your items will ship within 3 to 5 business days.",
    "Your appointment is confirmed for {d} at {tm}. Reply to this email if you need to reschedule.",
    "Hi {n}, here is the agenda for {d}: 1) review {t}, 2) next steps, 3) any other business.",
    "Thanks for your message. I will be out of office until {d} and will reply when I am back.",
    "Hi {n}, congratulations on finishing {t}, great work! Let us celebrate with lunch on {d}.",
    "Your monthly newsletter: three tips for organising your inbox, a short guide to spreadsheets, and a reading list.",
    "Hi {n}, I have booked the meeting room for {d} at {tm}. The video link is in the calendar invite.",
    "Invoice 2041 for last month is attached. Payment is due by the end of the month using the bank details already on file.",
    "Hi {n}, could you send over {t} when you get a chance? Thank you so much, I really appreciate your help.",
    "We have updated our privacy policy. You do not need to do anything, and you can read the changes on our website.",
    "Your package has shipped and will arrive on {d}. You can track it any time from your account on our site.",
    "Hi {n}, the transcript from {d} is ready. I highlighted the action items and decisions for {t}.",
    "Welcome aboard {n}! Your first week schedule is attached. Please bring your ID on {d}.",
]
L_LINK = ["https://meet.google.com/abc-defg-hij", "https://www.google.com/calendar", "https://zoom.us/j/123456789",
          "https://docs.google.com/document/d/abc123", "https://www.linkedin.com/in/example", "https://teams.microsoft.com/l/meetup-join/abc",
          "https://www.safaricom.co.ke/personal", "https://github.com/example/project"]


def phishing() -> str:
    parts = [random.choice(P_OPEN), random.choice(P_REASON).format(b=random.choice(BRANDS)), random.choice(P_ACTION) + "."]
    if random.random() < 0.85:
        parts.append(random.choice(P_LINK).format(
            d=random.choice(P_DOM), x="".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=6)), n=random.randint(2, 250)))
    c = random.choice(P_CLOSE)
    if c:
        parts.append(c)
    return " ".join(parts)


def legit() -> str:
    msg = random.choice(L_MSG).format(n=random.choice(NAMES), d=random.choice(DAYS), t=random.choice(TOPICS), tm=random.choice(TIMES))
    if random.random() < 0.4:
        msg += " " + random.choice(L_LINK)
    if random.random() < 0.5:
        msg += " " + random.choice(["Kind regards,", "Thanks,", "Best,", "Regards,"]) + " " + random.choice(NAMES)
    return msg


def main() -> None:
    rows = []
    seen = set()
    while len(rows) < 1200:
        label = len(rows) % 2
        text = phishing() if label else legit()
        if text in seen:
            continue
        seen.add(text)
        rows.append((text, label))
    random.shuffle(rows)
    out = os.path.join(os.path.dirname(__file__), "messages.csv")
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["text", "label"])
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
