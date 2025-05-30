from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from fpdf import FPDF
from flask_cors import CORS
import requests
import socket
import os
import re
import datetime

app = Flask(__name__)
CORS(app)

burp_logs = []

# --- Form Parsing for SQLi Testing ---
def get_all_forms(url):
    try:
        soup = BeautifulSoup(requests.get(url, timeout=5).content, "html.parser")
        return soup.find_all("form")
    except:
        return []

def get_form_details(form):
    details = {
        'action': form.attrs.get("action", "").lower(),
        'method': form.attrs.get("method", "get").lower(),
        'inputs': []
    }
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        details['inputs'].append({"type": input_type, "name": input_name})
    return details

def is_vulnerable(response):
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark",
        "you have an error in your sql syntax",
        "sql syntax error"
    }
    content = response.content.decode(errors='ignore').lower()
    return any(error in content for error in errors)

# --- XSS Testing ---
def is_xss_vulnerable(url):
    payload = "<script>alert('XSS')</script>"
    try:
        r = requests.get(url + "?input=" + payload, timeout=5)
        return payload in r.text
    except:
        return False

# --- Discover URLs from Page ---
def discover_urls(url):
    discovered = set()
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = urljoin(url, tag['href'])
            discovered.add(href)
    except:
        pass
    return list(discovered)

# --- Basic Port Scan ---
def get_ip_and_ports(url):
    domain = urlparse(url).netloc or url
    try:
        ip = socket.gethostbyname(domain)
    except:
        return "Unknown", []
    ports = []
    for port in [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]:
        try:
            with socket.create_connection((ip, port), timeout=1):
                ports.append(port)
        except:
            continue
    return ip, ports

# --- Tech Detection ---
def get_technologies(url):
    tech = []
    try:
        r = requests.get(url, timeout=5)
        if "X-Powered-By" in r.headers:
            tech.append(f"X-Powered-By: {r.headers['X-Powered-By']}")
        if "Server" in r.headers:
            tech.append(f"Server: {r.headers['Server']}")
        soup = BeautifulSoup(r.text, "html.parser")
        gen = soup.find("meta", {"name": "generator"})
        if gen:
            tech.append(f"Generator: {gen.get('content')}")
    except:
        pass
    return tech or ["Unknown"]

# --- Burp Log Analysis ---
def parse_burp_log(filepath):
    logs = []
    if os.path.exists(filepath):
        with open(filepath) as f:
            for line in f:
                log = line.strip()
                if log:
                    if re.search(r"(select|drop|--|alert|<script)", log, re.IGNORECASE):
                        logs.append(f"[!] Suspicious: {log}")
                    else:
                        logs.append(f"[+] Normal: {log}")
    return logs

# --- ROUTES ---
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    attack_types = data.get('attackTypes', [])

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    results = {
        "sql_injection": [],
        "xss": [],
        "burp_logs": [],
        "urls": [],
        "ip": "",
        "ports": [],
        "tech": [],
        "messages": []
    }

    burp_logs.clear()
    burp_logs.append(f"GET {url} HTTP/1.1")

    try:
        # Discover
        results["urls"] = discover_urls(url)

        # Tech/IP
        results["tech"] = get_technologies(url)
        results["ip"], results["ports"] = get_ip_and_ports(url)

        # SQLi
        if "sql" in attack_types:
            forms = get_all_forms(url)
            for form in forms:
                details = get_form_details(form)
                for input_tag in details["inputs"]:
                    if input_tag["name"]:
                        data = {input_tag["name"]: "' OR '1'='1"}
                        action_url = urljoin(url, details["action"])
                        if details["method"] == "post":
                            r = requests.post(action_url, data=data)
                        else:
                            r = requests.get(action_url, params=data)
                        burp_logs.append(f"{details['method'].upper()} {action_url} HTTP/1.1")
                        if is_vulnerable(r):
                            results["sql_injection"].append({
                                "url": action_url,
                                "form": details
                            })

        # XSS
        if "xss" in attack_types:
            for u in results["urls"]:
                if is_xss_vulnerable(u):
                    results["xss"].append(u)

        # Burp log
        results["burp_logs"] = parse_burp_log("burp_suite_log.txt")

        if not results["sql_injection"]:
            results["messages"].append("No SQL Injection found.")
        if not results["xss"]:
            results["messages"].append("No XSS vulnerabilities found.")

        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/download-report', methods=['POST'])
def download_report():
    data = request.json
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Vulnerability Scan Report", ln=True, align='C')
    pdf.ln(10)

    pdf.cell(200, 10, txt=f"IP Address: {data.get('ip', 'Unknown')}", ln=True)
    pdf.cell(200, 10, txt=f"Open Ports: {', '.join(map(str, data.get('ports', [])))}", ln=True)
    pdf.cell(200, 10, txt=f"Technologies: {', '.join(data.get('tech', []))}", ln=True)

    pdf.ln(10)
    pdf.cell(200, 10, txt="SQL Injection Results:", ln=True)
    if not data.get("sql_injection"):
        pdf.cell(200, 10, txt="No SQL vulnerabilities found.", ln=True)
    else:
        for item in data["sql_injection"]:
            pdf.multi_cell(0, 10, txt=f"Vulnerable: {item['url']}")

    pdf.ln(10)
    pdf.cell(200, 10, txt="XSS Results:", ln=True)
    if not data.get("xss"):
        pdf.cell(200, 10, txt="No XSS vulnerabilities found.", ln=True)
    else:
        for xss_url in data["xss"]:
            pdf.multi_cell(0, 10, txt=f"XSS Detected: {xss_url}")

    pdf.ln(10)
    pdf.cell(200, 10, txt="Burp Logs:", ln=True)
    for log in data.get("burp_logs", []):
        pdf.multi_cell(0, 10, txt=log)

    pdf_file = "report.pdf"
    pdf.output(pdf_file)
    return send_file(pdf_file, as_attachment=True)

# Note: Don't use app.run() in production. Use waitress or gunicorn.
