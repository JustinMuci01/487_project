#!/usr/bin/env python3
"""
Cookie Scanner: finds third-party / tracking cookies before and after consent.

Setup:
    pip install selenium tldextract
    Put Disconnect's services.json in the same folder as this script, then:
    python cookie_scanner.py https://example.com --max-pages 10 --consent accept

Uses Chrome + the DevTools Protocol, because driver.get_cookies() only returns
cookies for the current domain and would miss third-party cookies.
"""
import argparse
import csv
import json
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

import tldextract
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

SERVICES_FILE = Path("data/services.json")     # Disconnect list, in your local directory
CUSTOM_FILE = Path("data/entities.csv")  # optional extras: domain,category,company
# Disconnect also has a "Content" category (CDNs, video embeds); skipped by default.
CATEGORIES = {"Advertising", "Analytics", "Social", "Fingerprinting", "Cryptomining"}

SKIP_EXT = (".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".zip", ".mp4", ".mp3", ".css", ".js")

REPORT_DIR = Path("cookie_reports")  # reports are written to a folder

# Known consent-banner button IDs (OneTrust, Cookiebot, etc.)
CONSENT_SELECTORS = {
    "accept": [
        "#onetrust-accept-btn-handler",
        "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
        "#truste-consent-button",
        ".cc-allow", ".cc-dismiss",
    ],
    "reject": [
        "#onetrust-reject-all-handler",
        "#CybotCookiebotDialogBodyButtonDecline",
        ".cc-deny",
    ],
}
# Fallback: match visible button/link text
CONSENT_TEXT = {
    "accept": ["accept all", "accept cookies", "accept", "i agree", "agree", "allow all", "got it"],
    "reject": ["reject all", "decline all", "decline", "deny", "only necessary", "necessary only", "reject"],
}


# ---------------------------------------------------------------- domains
def registrable(host: str) -> str:
    """example.co.uk for www.example.co.uk (uses the public suffix list)."""
    ext = tldextract.extract((host or "").lstrip("."))
    return getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or host


def report_path(url_host: str, out_dir: Path = REPORT_DIR) -> Path:
    # extracts a report path:
    # cookie_reports/<name>_<YYYY-MM-DD>_report.json (youtube_2026-11-13_report.json)
    
    name = tldextract.extract(url_host).domain or url_host   # www.youtube.com -> youtube
    today = datetime.now().strftime("%Y-%m-%d")
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{name}_{today}_report.json"


def load_blocklist(services_path: Path = SERVICES_FILE) -> dict:
    """Parse Disconnect's services.json into {domain: {category, company}}."""
    if not services_path.exists():
        raise SystemExit(f"Could not find {services_path.resolve()}. "
                         "Put Disconnect's services.json there or pass --services PATH.")
    data = json.loads(services_path.read_text(encoding="utf-8"))
    out = {}
    for category, entries in data["categories"].items():
        if category not in CATEGORIES:
            continue
        for entry in entries:
            for company, sites in entry.items():
                for _homepage, domains in sites.items():
                    if not isinstance(domains, list):
                        continue
                    for d in domains:
                        out[d.lower()] = {"category": category, "company": company}
    # if CUSTOM_FILE.exists():
    #     with CUSTOM_FILE.open(newline="", encoding="utf-8") as f:
    #         for row in csv.DictReader(f):   # header: domain,category,company
    #             out[row["domain"].strip().lower()] = {
    #                 "category": row.get("category", "Custom"),
    #                 "company": row.get("company", "Custom"),
    #             }
    return out


def match_blocklist(cookie_domain: str, blocklist: dict):
    """Match the domain or any parent domain (a.b.tracker.com -> tracker.com)."""
    labels = cookie_domain.lstrip(".").lower().split(".")
    for i in range(len(labels) - 1):
        hit = blocklist.get(".".join(labels[i:]))
        if hit:
            return hit
    return None


# ---------------------------------------------------------------- browser
def make_driver(headless: bool):
    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--window-size=1366,900")
    opts.page_load_strategy = "normal"
    driver = webdriver.Chrome(options=opts)   # Selenium Manager fetches chromedriver
    driver.set_page_load_timeout(30)
    driver.execute_cdp_cmd("Network.enable", {})
    return driver


def click_consent(driver, mode: str) -> bool:
    for sel in CONSENT_SELECTORS[mode]:
        for el in driver.find_elements(By.CSS_SELECTOR, sel):
            try:
                if el.is_displayed():
                    el.click()
                    return True
            except WebDriverException:
                pass
    # Fallback: scan clickable elements by text (exact match first, then contains)
    clickables = driver.find_elements(
        By.XPATH, "//button | //a | //*[@role='button'] | //input[@type='button' or @type='submit']"
    )
    for exact in (True, False):
        for phrase in CONSENT_TEXT[mode]:
            for el in clickables:
                try:
                    text = (el.text or el.get_attribute("value") or "").strip().lower()
                    if not text or not el.is_displayed():
                        continue
                    if (text == phrase) if exact else (phrase in text and len(text) < 40):
                        el.click()
                        return True
                except WebDriverException:
                    continue
    return False   # banner may be in an iframe/shadow DOM, or not exist


def extract_links(driver, site: str):
    links = set()
    for a in driver.find_elements(By.TAG_NAME, "a"):
        try:
            href = a.get_attribute("href")
        except WebDriverException:
            continue
        if not href:
            continue
        href, _ = urldefrag(urljoin(driver.current_url, href))
        p = urlparse(href)
        if p.scheme in ("http", "https") and registrable(p.hostname) == site \
                and not p.path.lower().endswith(SKIP_EXT):
            links.add(href)
    return links


def crawl(driver, start, site, max_pages, wait, consent=None):
    cookies, visited, queue = {}, set(), deque([start])
    clicked = None
    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        print(f"  [{len(visited)}/{max_pages}] {url}")
        try:
            driver.get(url)
        except WebDriverException as e:
            print(f"    ! failed: {str(e).splitlines()[0][:80]}")
            continue
        time.sleep(wait)   # let trackers fire
        if consent and clicked is None:
            clicked = click_consent(driver, consent)
            print(f"    consent '{consent}' clicked: {clicked}")
            time.sleep(wait)
        for c in driver.execute_cdp_cmd("Network.getAllCookies", {})["cookies"]:
            cookies.setdefault((c["name"], c["domain"], c["path"]), {**c, "first_seen_on": url})
        for link in sorted(extract_links(driver, site)):
            if link not in visited:
                queue.append(link)
    return list(cookies.values()), sorted(visited), clicked


# ---------------------------------------------------------------- analysis
def analyze(cookies, site, blocklist):
    rows = []
    for c in cookies:
        hit = match_blocklist(c["domain"], blocklist)
        exp = c.get("expires", -1)
        rows.append({
            "name": c["name"],
            "domain": c["domain"],
            "path": c["path"],
            "expires": "session" if c.get("session") or exp in (-1, None)
                       else datetime.fromtimestamp(exp, tz=timezone.utc).isoformat(),
            "secure": c.get("secure"),
            "httpOnly": c.get("httpOnly"),
            "sameSite": c.get("sameSite", "unspecified"),
            "value": c["value"],
            "first_seen_on": c["first_seen_on"],
            "third_party": registrable(c["domain"]) != site,
            "flagged": bool(hit),
            "category": hit["category"] if hit else "",
            "company": hit["company"] if hit else "",
        })
    return rows


def print_report(label, rows):
    third = [r for r in rows if r["third_party"]]
    flagged = [r for r in rows if r["flagged"]]
    print(f"\n=== {label} ===")
    print(f"Total cookies:          {len(rows)}")
    print(f"Third-party cookies:    {len(third)}")
    print(f"On tracker blocklist:   {len(flagged)}")
    for r in flagged:
        print(f"  - {r['name']:<28} {r['domain']:<32} {r['company']} ({r['category']})")


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Third-party cookie scanner")
    ap.add_argument("url", nargs="?")
    ap.add_argument("--max-pages", type=int, default=10)
    ap.add_argument("--consent", choices=["accept", "reject"], default="accept",
                    help="which banner button to click for the 'after consent' scan")
    ap.add_argument("--wait", type=float, default=3.0, help="seconds to wait per page")
    ap.add_argument("--headed", action="store_true", help="show the browser window")
    ap.add_argument("--services", default=str(SERVICES_FILE),
                    help="path to Disconnect's services.json (default: ./services.json)")
    ap.add_argument("--out", default=None, help="output file (default: cookie_reports/<site>_<date>_report.json)") # was default="cookie_report.json" & help= wasn't there
    args = ap.parse_args()

    if not args.url:
        ap.error("please provide a URL to scan")
    url = args.url if args.url.startswith("http") else "https://" + args.url
    site = registrable(urlparse(url).hostname)
    blocklist = load_blocklist(Path(args.services))
    print(f"Scanning {url} (first-party site: {site}, {len(blocklist)} blocklisted domains)")

    # Phase 1: fresh browser, never touch the banner
    print("\nPhase 1: BEFORE consent")
    d = make_driver(not args.headed)
    try:
        raw, pages, _ = crawl(d, url, site, args.max_pages, args.wait)
    finally:
        d.quit()
    before = analyze(raw, site, blocklist)

    # Phase 2: another fresh browser (clean cookie jar), click the banner first
    print(f"\nPhase 2: AFTER consent ({args.consent})")
    d = make_driver(not args.headed)
    try:
        raw, pages2, clicked = crawl(d, url, site, args.max_pages, args.wait, consent=args.consent)
    finally:
        d.quit()
    after = analyze(raw, site, blocklist)

    print_report("BEFORE consent", before)
    print_report(f"AFTER consent ({args.consent}, button found: {clicked})", after)

    pre_flagged = [r for r in before if r["flagged"]]
    if pre_flagged:
        print(f"\n!! {len(pre_flagged)} known tracking cookies were set BEFORE the user interacted with the banner.")

    out_path = Path(args.out) if args.out else report_path(urlparse(url).hostname)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "url": url, "scanned_at": datetime.now(timezone.utc).isoformat(),
        "pages_before": pages, "pages_after": pages2, "consent_clicked": clicked,
        "before_consent": before, "after_consent": after,
    }, indent=2))
    print(f"\nFull report written to {out_path}")

if __name__ == "__main__":
    main()