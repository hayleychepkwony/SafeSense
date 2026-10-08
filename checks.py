"""SafeSense core: rule-based phishing checks that explain themselves.

Every check returns a Finding with a plain-English reason and a tip on what
to look at, so the person reading the report learns something instead of just
getting a yes/no answer. Standard library only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Data you can edit
# ---------------------------------------------------------------------------

# Brand name -> official registered domains. Extend this list for your region.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "safaricom": {"safaricom.co.ke"},
    "mpesa": {"safaricom.co.ke", "m-pesa.com"},
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
}

SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "click", "support", "country", "gq", "tk", "ml",
    "cf", "work", "link", "rest", "icu",
}

RISKY_ATTACHMENTS = r"(?:exe|scr|js|vbs|bat|cmd|jar|msi|iso|img|lnk|hta|docm|xlsm|zip|rar|7z)"

# Phrase groups: id -> (points, title, advice, phrases)
PHRASES: dict[str, tuple[int, str, str, list[str]]] = {
    "urgency": (
        10,
        "Pressure to act quickly",
        "Scammers rush you so you do not stop to think. Real organisations rarely demand action within hours.",
        ["urgent", "immediately", "within 24 hours", "within 48 hours", "act now",
         "final notice", "last warning", "expires today", "as soon as possible",
         "right away", "limited time"],
    ),
    "threat": (
        12,
        "Threat of losing an account or access",
        "Threats such as 'your account will be closed' are a classic way to scare people into clicking.",
        ["account will be suspended", "account has been suspended", "account locked",
         "account has been locked", "will be closed", "will be terminated",
         "unauthorized login", "unusual activity", "suspicious activity",
         "security alert", "has been compromised"],
    ),
    "credentials": (
        18,
        "Asks for passwords, codes or payment details",
        "Legitimate companies do not ask you to confirm passwords, PINs, OTP codes or card details by email or message.",
        ["verify your account", "confirm your password", "enter your password",
         "update your payment", "confirm your identity", "verify your identity",
         "login to verify", "log in to confirm", "sign in to confirm",
         "one-time password", "otp", "pin", "bank details", "card number", "cvv",
         "update your billing"],
    ),
    "reward": (
        12,
        "Unexpected prize, refund or reward",
        "If you did not enter a competition, you cannot win it. Prize and refund offers are used as bait.",
        ["you have won", "you've won", "lottery", "claim your prize",
         "claim your reward", "inheritance", "gift card", "free iphone",
         "congratulations"],
    ),
    "generic-greeting": (
        6,
        "Generic greeting instead of your name",
        "Companies that hold your account usually address you by name.",
        ["dear customer", "dear user", "dear client", "dear member",
         "dear account holder", "dear sir/madam", "valued customer"],
    ),
}

LEVEL_HIGH = 50
LEVEL_MEDIUM = 20

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    points: int
    advice: str
    evidence: str = ""


@dataclass
class Report:
    score: int
    level: str
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "urls": self.urls,
            "findings": [asdict(f) for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "or", "ne", "go", "sc"}


def registered_domain(host: str) -> str:
    """Approximate the registered domain (e.g. mail.google.com -> google.com).

    This is a simplification: it handles common patterns such as co.ke and
    com.au but is not a full Public Suffix List lookup.
    """
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if parts[-2] in _SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalize(text: str) -> str:
    """Undo common look-alike tricks: 0->o, 1->l, rn->m, vv->w."""
    text = text.lower().replace("rn", "m").replace("vv", "w")
    return text.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"}))


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _mentions(brand: str, text: str) -> bool:
    """Is the brand name used in this text?

    Short brand names must be a whole word (so 'pineapple' does not trigger
    'apple'); longer names can appear anywhere ('paypalsecure').
    """
    if brand in _tokens(text):
        return True
    return len(brand) >= 6 and brand in text.lower()


def _domain_findings(host: str, where: str) -> list[Finding]:
    """Check one hostname for brand misuse or look-alike spelling."""
    host = host.lower().strip(".")
    reg = registered_domain(host)
    normalized = _normalize(host)
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        if _mentions(brand, host):
            return [Finding(
                "brand-misuse",
                f"{where.capitalize()} uses the name '{brand}' but is not an official {brand} domain",
                30,
                f"The real {brand} sites end in {', '.join(sorted(official))}. "
                "Anything else, even if it contains the brand name, is not them.",
                host,
            )]
        if _mentions(brand, normalized):
            return [Finding(
                "lookalike-domain",
                f"{where.capitalize()} imitates '{brand}' with look-alike spelling",
                35,
                "Letters were swapped for similar-looking ones (for example 1 for l, 0 for o, rn for m). "
                "Read the address slowly, character by character.",
                host,
            )]
    return []


# ---------------------------------------------------------------------------
# URL checks
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def analyze_url(url: str, assumed_scheme: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return [Finding("malformed-url", "Link is malformed", 10,
                        "Broken or oddly formed links are sometimes used to hide the real destination.", url)]
    if not host:
        return findings

    if "@" in parsed.netloc:
        findings.append(Finding(
            "userinfo-trick", "Link hides its real destination using '@'", 25,
            "In a link, everything before the @ is ignored by the browser. The real site is the part after it.", url))
    if _IP_RE.fullmatch(host):
        findings.append(Finding(
            "ip-address-link", "Link goes to a raw IP address, not a website name", 25,
            "Legitimate services use proper domain names. A bare number is a warning sign.", host))
    else:
        if any(label.startswith("xn--") for label in host.split(".")):
            findings.append(Finding(
                "punycode", "Domain uses special characters that can imitate normal letters", 20,
                "Internationalised domains (xn--) can be made to look like a real brand.", host))
        if registered_domain(host) in SHORTENERS:
            findings.append(Finding(
                "shortener", "Link uses a URL shortener", 12,
                "Shortened links hide where you will really land. Preview them before opening.", host))
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            findings.append(Finding(
                "suspicious-tld", "Link ends in a domain type often used for scams", 8,
                "Not always malicious, but cheap endings like .top or .click are used heavily by scammers.", host))
        if len(host.split(".")) >= 5:
            findings.append(Finding(
                "many-subdomains", "Link has an unusually long chain of subdomains", 10,
                "Long chains can bury the real domain, which is always the last two parts before the first '/'.", host))
        findings.extend(_domain_findings(host, "link"))

    if parsed.scheme == "http" and not assumed_scheme:
        findings.append(Finding(
            "no-https", "Link is not encrypted (http, not https)", 8,
            "Real login and payment pages use https.", url))
    return findings


# ---------------------------------------------------------------------------
# Header and text checks
# ---------------------------------------------------------------------------

_HEADER_RE = re.compile(r"^(from|reply-to|return-path):[ \t]*(.+)$", re.I | re.M)
_ADDR_RE = re.compile(r"<([^<>\s]+@[^<>\s]+)>")
_BARE_ADDR_RE = re.compile(r"[^\s<>\"',;]+@[^\s<>\"',;]+")
_LINK_RE = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
_SHOWN_DOMAIN_RE = re.compile(r"((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


def _parse_address(value: str) -> tuple[str, str]:
    """Return (display_name, domain) from a header value."""
    m = _ADDR_RE.search(value)
    addr = m.group(1) if m else (_BARE_ADDR_RE.search(value) or [""])[0]
    name = value.split("<", 1)[0].strip().strip('"') if m else ""
    domain = addr.split("@")[-1].lower().strip(">.") if "@" in addr else ""
    return name, domain


def _header_findings(text: str) -> list[Finding]:
    headers: dict[str, tuple[str, str]] = {}
    for key, value in _HEADER_RE.findall(text):
        headers.setdefault(key.lower(), _parse_address(value))

    findings: list[Finding] = []
    if "from" in headers:
        name, domain = headers["from"]
        if domain:
            findings.extend(_domain_findings(domain, "sender"))
            for brand, official in BRANDS.items():
                if _mentions(brand, name) and registered_domain(domain) not in official:
                    findings.append(Finding(
                        "display-name-spoof",
                        f"Sender name says '{name}' but the address is not from {brand}",
                        25,
                        "Anyone can type any name into the 'From' field. Check the actual address, not the name.",
                        f"{name} <...@{domain}>",
                    ))
                    break
    for other in ("reply-to", "return-path"):
        if "from" in headers and other in headers:
            f_domain, o_domain = headers["from"][1], headers[other][1]
            if f_domain and o_domain and registered_domain(f_domain) != registered_domain(o_domain):
                findings.append(Finding(
                    "reply-mismatch",
                    f"Replies would go to a different domain than the sender ({other})",
                    18,
                    "If you reply, your message goes somewhere other than where the email claims to come from.",
                    f"from {f_domain} but {other} {o_domain}",
                ))
                break
    return findings


def _link_text_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for href, inner in _LINK_RE.findall(text):
        if not href.lower().startswith(("http://", "https://")):
            continue
        visible = re.sub(r"<[^>]+>", "", inner).strip()
        m = _SHOWN_DOMAIN_RE.search(visible)
        if not m:
            continue
        shown = m.group(1)
        shown_host = urlparse(shown if "//" in shown else "http://" + shown).hostname or ""
        real_host = urlparse(href).hostname or ""
        if shown_host and real_host and registered_domain(shown_host) != registered_domain(real_host):
            findings.append(Finding(
                "link-text-mismatch",
                "The link text shows one website but the link goes to another", 25,
                "Hover over links (or press and hold on a phone) to see where they really go before you click.",
                f"shows {shown_host} -> goes to {real_host}",
            ))
    return findings


def _phrase_findings(text: str) -> list[Finding]:
    lowered = text.lower()
    findings: list[Finding] = []
    for fid, (points, title, advice, phrases) in PHRASES.items():
        hits = [p for p in phrases if re.search(r"\b" + re.escape(p) + r"\b", lowered)]
        if hits:
            findings.append(Finding(fid, title, points, advice, ", ".join(hits[:3])))
    return findings


def _attachment_findings(text: str) -> list[Finding]:
    m = re.search(r"[\w\-. ]{1,60}\." + RISKY_ATTACHMENTS + r"\b", text, re.I)
    if not m:
        return []
    return [Finding(
        "risky-attachment", "Mentions an attachment type that can carry malware", 20,
        "Do not open unexpected .exe, .zip, .js or macro-enabled Office files, even from people you know, without confirming first.",
        m.group(0).strip(),
    )]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _level(score: int) -> str:
    if score >= LEVEL_HIGH:
        return "high"
    if score >= LEVEL_MEDIUM:
        return "medium"
    return "low"


def analyze(text: str) -> Report:
    """Analyse an email, message or single link and return an explained Report."""
    text = text or ""
    stripped = text.strip()
    assumed = False

    urls = [u.rstrip(".,;:!?") for u in _URL_RE.findall(text)]
    # A lone address typed without http:// (e.g. "paypa1-login.com/verify")
    if not urls and stripped and not re.search(r"\s", stripped) and "." in stripped and "@" not in stripped:
        urls = ["http://" + stripped]
        assumed = True
    urls = list(dict.fromkeys(urls))

    findings: list[Finding] = []
    for url in urls:
        findings.extend(analyze_url(url, assumed_scheme=assumed))
    findings.extend(_header_findings(text))
    findings.extend(_link_text_findings(text))
    findings.extend(_phrase_findings(text))
    findings.extend(_attachment_findings(text))

    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.id, f.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: -f.points)

    score = min(100, sum(f.points for f in unique))
    return Report(score=score, level=_level(score), findings=unique, urls=urls)
