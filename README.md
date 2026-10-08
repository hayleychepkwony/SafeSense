# SafeSense

An explainable phishing checker. Paste a suspicious email, text message or link, and SafeSense gives it a risk level **and tells you why**, so people learn what to look for instead of just getting a yes/no answer.

> Personal learning project. It is a rule-based helper, not a replacement for a professional email security product.

## What it checks

| Area | Examples |
|---|---|
| **Links** | look-alike spelling (`paypa1.com`, `rnicrosoft.com`), brand names on unofficial domains, raw IP addresses, `@` tricks, punycode, URL shorteners, odd domain endings, very long subdomain chains, missing HTTPS |
| **Sender** | display name pretending to be a brand, sender domain imitating a brand, `Reply-To` pointing somewhere else |
| **HTML links** | link text shows one website but the link goes to another |
| **Wording** | pressure to act fast, account-suspension threats, requests for passwords / PIN / OTP / card details, surprise prizes, generic greetings |
| **Attachments** | file types that commonly carry malware (`.exe`, `.zip`, `.js`, macro Office files, etc.) |

Each finding adds points. The total (capped at 100) becomes **LOW** (0-19), **MEDIUM** (20-49) or **HIGH** (50+), and every finding includes the evidence and a plain-English tip on what to check.

## Quick start

Requires Python 3.9+. No packages to install.

```bash
# Check a file
python -m safesense samples/phishing_1_paypal.txt

# Check text from the clipboard / another command
echo "http://bit.ly/claim-prize" | python -m safesense -

# Machine-readable output
python -m safesense samples/phishing_2_prize.txt --json

# Local web page at http://127.0.0.1:8000 (nothing leaves your computer)
python -m safesense.web
```

### Example output

```
SafeSense report
Risk level: HIGH   (score 100/100)

Why:
 1. [+35] Link imitates 'paypal' with look-alike spelling
      Evidence: paypa1-secure.example.com
      What to check: Letters were swapped for similar-looking ones...
 2. [+25] Sender name says 'PayPal Support' but the address is not from paypal
 3. [+25] The link text shows one website but the link goes to another
      Evidence: shows www.paypal.com -> goes to paypa1-secure.example.com
 4. [+18] Replies would go to a different domain than the sender (reply-to)
 ...
```

A normal message scores low:

```
Risk level: LOW   (score 0/100)
No warning signs were found by the current rules.
```

## Project structure

```
safesense/
  checks.py     the rules and scoring (start here)
  cli.py        command-line interface
  web.py        small local web page (standard library only)
samples/        example phishing and legitimate messages (fake, safe to open)
tests/          unit tests
```

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## How the look-alike detection works

Hostnames are normalised (`1`→`l`, `0`→`o`, `rn`→`m`, `vv`→`w`) and compared with a list of known brands. If a brand only appears *after* normalising, the domain is imitating it. Short brand names such as `apple` must be a whole word, so `pineapple-recipes.com` is not flagged. The brand list is in `checks.py` and is easy to extend, for example with local banks.

## Limitations (please read)

- **Rule-based, not machine learning.** It catches common, known tricks. A carefully written phishing message that avoids them can score low.
- **A LOW score is not a guarantee of safety.** Always verify unexpected requests through a channel you already trust.
- **Small brand list** and a simplified way of finding the registered domain (it does not use the full Public Suffix List).
- **English-language wording only.** Phrase lists are in English.
- It does not open links, scan attachments or check domain age or reputation.
- Scores and thresholds are judgement-based and have not been validated on a large real-world dataset.

## Safety and ethics

- Everything runs locally; no message content is sent anywhere.
- All sample domains use reserved test domains (`example.com`, `example.net`) or documentation IP ranges, and no live phishing links.
- This is a defensive tool for awareness and education.

## Ideas for next steps

- Check domain age and reputation through an optional lookup
- Parse real `.eml` files and full email headers (SPF / DKIM / DMARC results)
- Add Swahili and other languages to the phrase lists
- Measure accuracy on a public labelled dataset and report precision / recall
- Browser extension front-end

## Author

Hayley Chepkemoi: Cybersecurity & Technical Virtual Assistant. [Portfolio](https://hayleychepkwony.github.io)

## License

MIT, see [LICENSE](LICENSE).
