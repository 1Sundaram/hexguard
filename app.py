from flask import Flask, render_template, request, jsonify, send_file
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import os
from fpdf import FPDF

app = Flask(__name__)

# Simulated burp-style logs for educational/demo purposes
burp_logs = []

def get_all_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = ""
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def is_vulnerable(response):
    errors = {"quoted string not properly terminated", "unclosed quotation mark", "you have an error in your sql syntax"}
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.json.get('url')
    attack_types = request.json.get('attackTypes', [])

    results = {
        "sql_injection": [],
        "burp_logs": [],
        "messages": []
    }

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        # Add initial request to burp-style log
        burp_logs.clear()
        burp_logs.append(f"GET {target_url} HTTP/1.1")

        if "sql" in attack_types:
            forms = get_all_forms(target_url)
            if not forms:
                results["messages"].append("No forms found to test for SQL Injection.")
            for form in forms:
                details = get_form_details(form)
                for input_tag in details["inputs"]:
                    data = {}
                    if input_tag["name"]:
                        data[input_tag["name"]] = "' OR '1'='1"
                        url = urljoin(target_url, details["action"])
                        if details["method"] == "post":
                            r = requests.post(url, data=data)
                            burp_logs.append(f"POST {url} HTTP/1.1")
                        else:
                            r = requests.get(url, params=data)
                            burp_logs.append(f"GET {url} HTTP/1.1")
                        if is_vulnerable(r):
                            results["sql_injection"].append({"form": details, "url": url})
        else:
            results["messages"].append("SQL Injection test not selected.")

        # Simulate adding burp logs from log file (optional)
        burp_file_path = "burp_suite_log.txt"
        if os.path.exists(burp_file_path):
            with open(burp_file_path) as f:
                for line in f:
                    if line.strip():
                        burp_logs.append(line.strip())
        else:
            results["messages"].append("Burp Suite log file not found.")

        results["burp_logs"] = burp_logs or ["No traffic captured during scan."]

        if not results["sql_injection"]:
            results["messages"].append("No SQL Injection vulnerabilities found.")

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/download-report', methods=['POST'])
def download_report():
    data = request.json
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="HexGuard Scan Report", ln=True, align='C')

    pdf.ln(10)
    pdf.cell(200, 10, txt="SQL Injection Results:", ln=True)

    if not data.get("sql_injection"):
        pdf.cell(200, 10, txt="No SQL vulnerabilities found.", ln=True)
    else:
        for item in data["sql_injection"]:
            pdf.multi_cell(0, 10, txt=f"Vulnerable Form at: {item['url']}")

    pdf.ln(5)
    pdf.cell(200, 10, txt="Burp Logs:", ln=True)

    if not data.get("burp_logs"):
        pdf.cell(200, 10, txt="No burp logs found.", ln=True)
    else:
        for log in data["burp_logs"]:
            pdf.multi_cell(0, 10, txt=log)

    pdf_output = "report.pdf"
    pdf.output(pdf_output)

    return send_file(pdf_output, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
