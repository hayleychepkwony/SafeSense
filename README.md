# SafeSense: Phishing Detection System

Paste a suspicious email, text message or link, and SafeSense tells you how risky it is **and why**. A rules engine and a machine-learning classifier each score the message, and the two are blended into one risk level with a plain-English explanation of every warning sign.

![SafeSense home](docs/home.png)

![A phishing email flagged as high risk](docs/result-phishing.png)

## How it works

| Layer | What it does |
|---|---|
| **Rules engine** | Inspects links (look-alike spelling like `paypa1.com`, brand names on unofficial domains, raw IPs, `@` tricks, punycode, URL shorteners, odd endings), the sender (display-name spoofing, `Reply-To` mismatch), HTML links whose text and destination differ, risky attachments, and pressure or credential-harvesting wording. |
| **ML classifier** | A scikit-learn pipeline (TF-IDF word and bigram features + logistic regression) that estimates the probability a message is phishing, and surfaces the words that influenced it. |
| **Verdict** | `final score = 0.6 × rules + 0.4 × ML probability`, mapped to **LOW** (0-19), **MEDIUM** (20-49) or **HIGH** (50+). |

![A normal email scored low](docs/result-safe.png)

## Tech stack

Python · Flask · scikit-learn · joblib · vanilla JavaScript front end (canvas animation, no framework)

## Run it locally

Requires Python 3.9 or newer.

```bash
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**. Use the example buttons, or paste your own message.

### Command line

```bash
python -m safesense samples/phishing_1_paypal.txt
echo "http://bit.ly/claim-prize" | python -m safesense -
python -m safesense samples/phishing_2_prize.txt --json
```

### API

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Your account has been suspended. Verify your password now."}'
```

Returns `score`, `level`, `rule_score`, `ml_probability`, `ml_signals`, `urls` and a list of `findings`, each with evidence and advice.

## Deploy it

The repo includes a `Procfile` and `render.yaml`, so it can run on any Python host. On [Render](https://render.com): **New → Web Service**, connect the repo, and it picks up the settings automatically (free plan works).

## Project structure

```
app.py                 Flask app and /api/analyze endpoint
safesense/
  checks.py            rules engine
  ml.py                model training and prediction
  engine.py            blends rules + ML into the final verdict
  cli.py               command-line interface
templates/ static/     web interface
data/                  labelled sample dataset + build script
models/                trained model (phish_model.joblib)
samples/               example messages (all fake, safe to open)
tests/                 25 unit and API tests
```

## Retrain the model

```bash
python data/build_dataset.py     # regenerate data/messages.csv
python -m safesense.ml           # train and save models/phish_model.joblib
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Limitations

- The model is trained on a **small bundled sample dataset** of generated messages, so it recognises common phishing wording but has not been validated on large real-world data. Swapping in a public labelled phishing corpus is the main next step.
- The rules cover well-known tricks; a carefully written message that avoids them can score low. **A low score does not prove a message is safe.**
- Brand list and domain parsing are simplified, wording rules are English only, and links and attachments are not opened or scanned.
- Messages are analysed in memory and are not stored.
- All sample domains use reserved test domains (`example.com`, `example.net`) or documentation IP ranges.
