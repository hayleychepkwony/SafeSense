"""Tiny local web page for SafeSense. Run: python -m safesense.web

Serves on 127.0.0.1 only. Nothing is stored and nothing leaves your computer.
"""
from __future__ import annotations

import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from .checks import analyze

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeSense</title>
<style>
 :root{{--bg:#0b0c0d;--panel:#14171a;--line:#2e3338;--text:#e9e7e2;--muted:#8f9399;--ok:#7ee0b8;--mid:#e9b44c;--bad:#e5707e}}
 *{{box-sizing:border-box}}
 body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,sans-serif}}
 main{{max-width:760px;margin:0 auto;padding:40px 20px 80px}}
 h1{{font-size:28px;margin:0 0 6px}} p.sub{{color:var(--muted);margin:0 0 24px}}
 textarea{{width:100%;min-height:200px;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:14px;font:14px/1.5 ui-monospace,monospace}}
 button{{margin-top:12px;background:var(--ok);color:#06130e;border:0;border-radius:999px;padding:12px 24px;font-weight:600;cursor:pointer}}
 .res{{margin-top:32px;border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:22px}}
 .badge{{display:inline-block;padding:4px 14px;border-radius:999px;font-weight:700;font-size:14px}}
 .low{{background:rgba(126,224,184,.15);color:var(--ok)}} .medium{{background:rgba(233,180,76,.15);color:var(--mid)}} .high{{background:rgba(229,112,126,.15);color:var(--bad)}}
 li{{margin:14px 0}} small{{display:block;color:var(--muted)}} code{{color:var(--mid);word-break:break-all}}
 .note{{color:var(--muted);font-size:14px;margin-top:18px}}
</style></head><body><main>
<h1>SafeSense</h1>
<p class="sub">Paste a suspicious email, message or link. It stays on your computer.</p>
<form method="post" action="/"><textarea name="text" placeholder="Paste here...">{text}</textarea>
<button type="submit">Check it</button></form>{result}
</main></body></html>"""


def render_result(text: str) -> str:
    if not text.strip():
        return ""
    r = analyze(text)
    items = "".join(
        f"<li><b>{html.escape(f.title)}</b> <small>+{f.points} points</small>"
        + (f"<small>Evidence: <code>{html.escape(f.evidence)}</code></small>" if f.evidence else "")
        + f"<small>What to check: {html.escape(f.advice)}</small></li>"
        for f in r.findings
    ) or "<li>No warning signs were found by the current rules.</li>"
    return (
        f'<section class="res"><span class="badge {r.level}">{r.level.upper()} RISK</span> '
        f"&nbsp;score {r.score}/100<ul>{items}</ul>"
        '<p class="note">SafeSense is a rule-based helper, not a guarantee. A low result does not prove '
        "a message is safe. If unsure, contact the sender using details you already trust.</p></section>"
    )


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, status: int = 200) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        self._send(PAGE.format(text="", result=""))

    def do_POST(self) -> None:  # noqa: N802
        length = min(int(self.headers.get("Content-Length", 0) or 0), 200_000)
        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        text = form.get("text", [""])[0]
        self._send(PAGE.format(text=html.escape(text), result=render_result(text)))

    def log_message(self, *args) -> None:  # keep the terminal quiet
        pass


def main(port: int = 8000) -> None:
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"SafeSense running at http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
