# Privacy Scanner 🔍

A lightweight **Scanner Developer** starter that crawls a website using `requests` + `BeautifulSoup`,
tries to find the Privacy Policy link, collects `Set-Cookie` headers, and flags likely third‑party trackers.

## Quick start
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt

python scanner/scanner.py --url https://example.com --max-pages 30 > data/example.com.jsonl
```

## Structure
```
scanner/   → core Python crawler
data/      → output JSONL files
rules.yml  → tracker domains & keywords
```

## Notes
- This stage is *static* (no clicking banners). Selenium automation is a separate role.
- Respect sites: we read robots.txt, set a User‑Agent, and limit pages.
