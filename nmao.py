import subprocess
from flask import Flask, request, render_template, jsonify

app = Flask(__name__)

def get_nmap(target, ip):
    try:
        # Construct the nmap command
        command = ["nmap", target, ip]
        
        # Run the command and capture the output and error
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            # If nmap fails, capture and print the error
            return f"Error: {result.stderr}"
        
        # Return the output of the nmap command
        return result.stdout
    except Exception as e:
        return f"An error occurred: {e}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    # Get the IP address from the form
    ip_address = request.form.get('ip')
    
    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400
    
    # Run the Nmap scan
    scan_result = get_nmap('-F', ip_address)
    
    # Return the scan result to the user
    return render_template('result.html', scan_result=scan_result)

if __name__ == '__main__':
    app.run(debug=True, port=5500)
