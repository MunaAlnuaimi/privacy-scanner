import argparse, time, json, queue, re
from urllib.parse import urljoin, urlparse
from urllib import robotparser

import requests
from bs4 import BeautifulSoup
import tldextract
import yaml

UA = "PrivacyScanner/1.0 (+https://example.local)"
PRIVACY_WORDS = ["privacy", "policy", "cookie", "cookies", "data", "pdpl", "gdpr"]

def load_rules(path="rules.yml"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            y = yaml.safe_load(f) or {}
    except FileNotFoundError:
        y = {}
    return set(y.get("third_party_domains", [])), set(y.get("keywords", []))

def same_site(a, b):
    da = tldextract.extract(a).registered_domain
    db = tldextract.extract(b).registered_domain
    return da and da == db

def score_privacy_link(text, href):
    text = (text or "").lower()
    href = (href or "").lower()
    score = 0
    for w in PRIVACY_WORDS:
        if w in text: score += 3
        if w in href: score += 2
    score -= href.count("/") * 0.2
    return score

def find_privacy_link(soup, base):
    best = (0, None)
    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        s = score_privacy_link(a.get_text(strip=True), href)
        if s > best[0]:
            best = (s, href)
    return best[1] if best[0] >= 3 else None

def extract_scripts(soup, base):
    out = []
    for s in soup.find_all("script"):
        if s.has_attr("src"):
            out.append(("src", urljoin(base, s["src"]), None))
        else:
            code = s.get_text()[:4000]
            out.append(("inline", None, code))
    return out

def domain_of(url):
    ext = tldextract.extract(url)
    if not ext.suffix: return ""
    return f"{ext.domain}.{ext.suffix}"

def detect_trackers(scripts, domain_rules, kw_rules):
    hits = []
    for kind, src, code in scripts:
        if src:
            d = domain_of(src)
            if any(d.endswith(rule) for rule in domain_rules):
                hits.append({"rule": d, "where": "script-src", "url": src})
        else:
            code_low = (code or "").lower()
            for kw in kw_rules:
                if kw.lower() in code_low:
                    hits.append({"rule": kw, "where": "inline-script", "url": None})
    return hits

def allowed_by_robots(target):
    parsed = urlparse(target)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = robotparser.RobotFileParser()
    try:
        rp.set_url(robots_url)
        rp.read()
    except Exception:
        return True
    return rp.can_fetch(UA, target)

def fetch(url, session):
    for attempt in range(3):
        try:
            t0 = time.time()
            r = session.get(url, timeout=15, allow_redirects=True)
            dt = int((time.time() - t0) * 1000)
            return r, dt
        except requests.RequestException:
            time.sleep(1 + attempt)
    return None, None

def crawl(start_url, max_pages=40, same_domain_only=True):
    session = requests.Session()
    session.headers["User-Agent"] = UA
    q = queue.Queue()
    q.put(start_url)
    visited = set()
    domain_rules, kw_rules = load_rules()
    results = []

    while not q.empty() and len(visited) < max_pages:
        url = q.get()
        if url in visited: continue
        visited.add(url)
        if not allowed_by_robots(url):
            results.append({"scanned_url": url, "notes": ["robots_disallow"]})
            continue

        resp, dt = fetch(url, session)
        if not resp:
            results.append({"scanned_url": url, "notes": ["fetch_failed"]})
            continue

        page = {
            "scanned_url": url,
            "final_url": str(resp.url),
            "status": resp.status_code,
            "response_ms": dt,
            "set_cookies": resp.headers.get("Set-Cookie", "").split(", ") if resp.headers.get("Set-Cookie") else [],
            "third_party_scripts": [],
            "tracker_hits": [],
            "privacy_policy_url": None,
            "privacy_policy_status": None,
            "notes": []
        }

        if "text/html" in resp.headers.get("Content-Type","") and resp.text:
            soup = BeautifulSoup(resp.text, "html.parser")
            ppol = find_privacy_link(soup, resp.url)
            if ppol:
                page["privacy_policy_url"] = ppol
                r2, _ = fetch(ppol, session)
                if r2:
                    page["privacy_policy_status"] = r2.status_code

            scripts = extract_scripts(soup, resp.url)
            page["third_party_scripts"] = [{"src": s[1]} for s in scripts if s[1]]
            page["tracker_hits"] = detect_trackers(scripts, domain_rules, kw_rules)

            for a in soup.find_all("a", href=True):
                href = urljoin(resp.url, a["href"])
                if same_domain_only and not same_site(start_url, href): 
                    continue
                if href.startswith("http") and href not in visited:
                    q.put(href)

        results.append(page)
    return results

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--max-pages", type=int, default=40)
    args = ap.parse_args()
    out = crawl(args.url, max_pages=args.max_pages)
    for row in out:
        print(json.dumps(row, ensure_ascii=False))
