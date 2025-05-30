import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import datetime
import socket
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- Vulnerability Check Functions ---
def is_sql_injection_vulnerable(url):
    payloads = ["' OR '1'='1", "' OR 'x'='x", "' --"]
    vulnerable_payloads = []
    for payload in payloads:
        try:
            response = requests.get(url + "?id=" + payload, timeout=5)
            if re.search(r"error|warning|sql", response.text, re.IGNORECASE):
                vulnerable_payloads.append(payload)
        except:
            continue
    return vulnerable_payloads

def is_xss_vulnerable(url):
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url + "?input=" + payload, timeout=5)
        if payload in response.text:
            return payload
    except:
        pass
    return None

def parse_burp_log(log_file):
    burp_logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as file:
            lines = file.readlines()
            for line in lines:
                burp_logs.append(line.strip())
    analyzed_logs = analyze_burp_logs(burp_logs)
    return analyzed_logs

def analyze_burp_logs(burp_logs):
    analyzed_logs = []
    for log in burp_logs:
        # Example: Check for SQLi or XSS patterns in the Burp Suite logs
        if re.search(r"union|select|drop|--|alert|<script>", log, re.IGNORECASE):
            analyzed_logs.append(f"Potential issue found: {log}")
        else:
            analyzed_logs.append(f"Normal log: {log}")
    return analyzed_logs

# --- Discovery & Scanning ---
def discover_urls(url):
    discovered_urls = []
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            for anchor_tag in soup.find_all("a"):
                href = anchor_tag.get("href")
                if href:
                    absolute_url = urljoin(url, href)
                    discovered_urls.append(absolute_url)
    except:
        pass
    return discovered_urls

# --- Target Info ---
def get_ip_and_ports(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path
    try:
        ip_address = socket.gethostbyname(domain)
    except:
        ip_address = "Unknown"
        return ip_address, []
    open_ports = []
    for port in [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]:
        try:
            with socket.create_connection((ip_address, port), timeout=1):
                open_ports.append(port)
        except:
            continue
    return ip_address, open_ports

# --- Technology Detection ---
def get_technologies(url):
    technologies = []
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            if soup.find("meta", {"name": "generator"}):
                technologies.append(f"Generator: {soup.find('meta', {'name': 'generator'}).get('content')}")
            if "X-Powered-By" in response.headers:
                technologies.append(f"X-Powered-By: {response.headers['X-Powered-By']}")
            if "Server" in response.headers:
                technologies.append(f"Server: {response.headers['Server']}")
    except:
        pass
    return technologies if technologies else ["Unknown"]

# --- HTML Report ---
def generate_html_report(url, discovered_urls, vulnerabilities, burp_logs, ip_address, open_ports, technologies):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = f"""
    <html>
    <head>
        <title>Vulnerability Scan Report</title>
        <style>
            body {{ font-family: Arial; }}
            h1 {{ color: #333366; }}
            h2 {{ color: #cc0000; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            tr:hover {{ background-color: #f2f2f2; }}
            .highlight {{ color: #cc0000; }}
        </style>
    </head>
    <body>
        <h1>Vulnerability Scan Report for {url}</h1>
        <p><strong>Scan Time:</strong> {timestamp}</p>

        <h2>Target Information</h2>
        <p><strong>IP Address:</strong> {ip_address}</p>
        <p><strong>Open Ports:</strong> {', '.join(map(str, open_ports))}</p>
        <p><strong>Technologies Detected:</strong> {', '.join(technologies)}</p>

        <h2>Discovered URLs:</h2>
        <ul>
    """
    for u in discovered_urls:
        html_content += f"<li>{u}</li>"
    html_content += "</ul><h2>Vulnerabilities Found:</h2>"
    for page_url, page_vulnerabilities in vulnerabilities.items():
        html_content += f"<h3>{page_url}</h3><ul>"
        for vuln, details in page_vulnerabilities.items():
            html_content += f"<li><strong>{vuln}</strong>: {details['description']}</li>"
            html_content += f"<li><strong>Payload:</strong> {details['payload']}</li>"
            html_content += f"<li><strong>Location:</strong> {details['location']}</li>"
        html_content += "</ul>"

    html_content += "<h2>Burp Suite Logs Analysis:</h2><pre>"
    if burp_logs:
        for log in burp_logs:
            html_content += f"{log}\n"
    else:
        html_content += "No Burp Suite logs available.\n"
    
    html_content += "</pre></body></html>"

    # Save the report
    with open("vulnerability_scan_report.html", "w") as file:
        file.write(html_content)

    return "Scan completed. Check the generated report."

# --- Flask Route ---
@app.route('/scan', methods=['POST'])
def scan_website():
    if request.is_json:
        data = request.get_json()
        url = data.get('url')
        options = data.get('options', {})

        discovered_urls = discover_urls(url)
        vulnerabilities = {}
        output_lines = [f"Scanning: {url}", f"Discovered {len(discovered_urls)} URLs"]

        if options.get('sql') or options.get('xss'):
            for page_url in discovered_urls:
                page_vulns = {}
                if options.get('sql'):
                    sql_payloads = is_sql_injection_vulnerable(page_url)
                    if sql_payloads:
                        for payload in sql_payloads:
                            page_vulns["SQL Injection"] = {
                                "description": "Possible SQL Injection detected.",
                                "payload": payload,
                                "location": page_url
                            }
                if options.get('xss'):
                    xss_payload = is_xss_vulnerable(page_url)
                    if xss_payload:
                        page_vulns["XSS"] = {
                            "description": "Possible XSS vulnerability detected.",
                            "payload": xss_payload,
                            "location": page_url
                        }
                if page_vulns:
                    vulnerabilities[page_url] = page_vulns

        burp_logs = parse_burp_log("burp_suite_log.txt") if options.get('burp') else []
        ip_address, open_ports = get_ip_and_ports(url) if options.get('ports') else ('Unknown', [])
        technologies = get_technologies(url) if options.get('tech') else []

        output_lines.append(f"IP Address: {ip_address}")
        output_lines.append(f"Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}")
        output_lines.append(f"Technologies: {', '.join(technologies)}")

        if vulnerabilities:
            output_lines.append("\nVulnerabilities Found:")
            for page_url, vulns in vulnerabilities.items():
                output_lines.append(f"\n  {page_url}")
                for vuln_type, details in vulns.items():
                    output_lines.append(f"    - {vuln_type}: {details['description']}")
                    output_lines.append(f"    - Payload: {details['payload']}")
                    output_lines.append(f"    - Location: {details['location']}")
        else:
            output_lines.append("\nNo vulnerabilities found.")

        if burp_logs:
            output_lines.append("\nBurp Suite Logs:")
            output_lines.extend(burp_logs[:5])  # First few lines

        generate_html_report(url, discovered_urls, vulnerabilities, burp_logs, ip_address, open_ports, technologies)

        return jsonify({'output': '\n'.join(output_lines)})
    else:
        return jsonify({'error': 'Invalid request, JSON expected.'}), 400

if __name__ == "__main__":
    app.run(debug=True, port=5500)
