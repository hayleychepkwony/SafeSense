"""Command-line interface: python -m safesense <file|-> [--json]"""
from __future__ import annotations

import argparse
import json
import sys

from .engine import scan

LIMITS = (
    "Note: SafeSense is a decision aid, not a guarantee. A LOW result does not "
    "prove a message is safe. When in doubt, contact the sender using a number or "
    "website you already trust."
)

LABELS = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH"}


def format_report(r: dict) -> str:
    ml = "n/a" if r["ml_probability"] is None else f"{round(r['ml_probability'] * 100)}%"
    lines = [
        "SafeSense report",
        "=" * 16,
        f"Risk level: {LABELS[r['level']]}   (score {r['score']}/100)",
        f"Rules engine: {r['rule_score']}/100   ML model confidence: {ml}",
        "",
    ]
    if r["urls"]:
        lines.append("Links found:")
        lines.extend(f"  - {u}" for u in r["urls"])
        lines.append("")
    if r["findings"]:
        lines.append("Why:")
        for i, f in enumerate(r["findings"], 1):
            lines.append(f" {i}. [+{f['points']}] {f['title']}")
            if f["evidence"]:
                lines.append(f"      Evidence: {f['evidence']}")
            lines.append(f"      What to check: {f['advice']}")
    else:
        lines.append("No warning signs were found by the rules engine.")
    lines += ["", LIMITS]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="safesense",
        description="Check an email, message or link for phishing warning signs.",
    )
    parser.add_argument("source", help="Path to a text file, or - to read from standard input")
    parser.add_argument("--json", action="store_true", help="Print the report as JSON")
    args = parser.parse_args(argv)

    try:
        if args.source == "-":
            text = sys.stdin.read()
        else:
            with open(args.source, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except OSError as exc:
        print(f"Could not read input: {exc}", file=sys.stderr)
        return 2

    report = scan(text)
    print(json.dumps(report, indent=2) if args.json else format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
