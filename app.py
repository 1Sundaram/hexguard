import os
import datetime
import re
import requests
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates"
)
CORS(app)

# make `now()` available in templates
@app.context_processor
def inject_now():
    return {"now": datetime.datetime.now}

# configuration
HACKERTARGET_API_BASE = "http://api.hackertarget.com"
MAX_PAGES = 10
HEADERS = {"User-Agent": "HexGuardScanner/1.0"}

def requests_get(url, **kwargs):
    return requests.get(url, timeout=5, headers=HEADERS, **kwargs)

def get_domain(url):
    p = urlparse(url)
    return p.netloc or p.path

def discover_urls(base_url):
    """Fetch base_url, return up to MAX_PAGES unique links."""
    try:
        r = requests_get(base_url)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        links = {
            urljoin(base_url, a["href"])
            for a in soup.find_all("a", href=True)
        }
        return list(links)[:MAX_PAGES]
    except:
        return []

def is_sql_vulnerable(page_url):
    payloads = ["' OR '1'='1", "'--", "' OR 'x'='x"]
    found = []
    for p in payloads:
        try:
            r = requests_get(f"{page_url}?id={p}")
            if re.search(r"sql|error|warning", r.text, re.I):
                found.append(p)
        except:
            pass
    return found

def is_xss_vulnerable(page_url):
    payload = "<script>alert(1)</script>"
    try:
        r = requests_get(f"{page_url}?input={payload}")
        return payload in r.text
    except:
        return False

def free_port_scan(url):
    domain = get_domain(url)
    r = requests_get(f"{HACKERTARGET_API_BASE}/nmap/?q={domain}")
    return r.text if r.ok else f"Error: {r.text}"

def free_tech_detect(url):
    domain = get_domain(url)
    r = requests_get(f"{HACKERTARGET_API_BASE}/httpheaders/?q={domain}")
    return r.text if r.ok else f"Error: {r.text}"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    url  = data.get("url", "").strip()
    opts = data.get("options", {})
    if not url:
        return jsonify(error="URL is required"), 400

    log_lines = []
    discovered = discover_urls(url)
    log_lines.append(f"Discovered {len(discovered)} pages (max {MAX_PAGES})")

    vulns = {}
    for page in discovered:
        page_v = {}
        if opts.get("sql"):
            sql = is_sql_vulnerable(page)
            if sql:
                page_v["sql"] = sql
        if opts.get("xss") and is_xss_vulnerable(page):
            page_v["xss"] = True
        if page_v:
            vulns[page] = page_v
    if opts.get("ports"):
        log_lines.append("=== Port Scan ===")
        log_lines.append(free_port_scan(url))
    if opts.get("tech"):
        log_lines.append("=== Tech Detect ===")
        log_lines.append(free_tech_detect(url))
    if opts.get("burp"):
        log_lines.append("=== Burp Suite Logs ===")
        if os.path.exists("burp_suite_log.txt"):
            with open("burp_suite_log.txt") as f:
                log_lines.extend(line.strip() for line in f)
        else:
            log_lines.append("(no burp_suite_log.txt)")

    if vulns:
        log_lines.append("=== Vulnerabilities Found ===")
        for p, vs in vulns.items():
            types = ", ".join(vs.keys())
            log_lines.append(f"– {p}: {types}")
    else:
        log_lines.append("No SQLi or XSS vulnerabilities found.")

    report_name = f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    return jsonify(output="\n".join(log_lines), report=report_name, vulns=vulns)

@app.route("/api/report", methods=["POST"])
def api_report():
    data = request.get_json(force=True)
    url       = data.get("url", "")
    vulns     = data.get("vulns", {})
    discovered = discover_urls(url)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = render_template(
        "report.html",
        url=url,
        timestamp=timestamp,
        discovered=discovered,
        vulns=vulns
    )
    name = f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(name, "w", encoding="utf-8") as f:
        f.write(html)
    return jsonify(report=name)

@app.route("/download/<path:filename>")
def download(filename):
    return send_file(
        filename,
        as_attachment=True,
        download_name=filename,
        mimetype="text/html"
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5500))
    app.run(debug=True, host="0.0.0.0", port=port)
