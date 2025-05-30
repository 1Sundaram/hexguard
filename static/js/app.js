const API_BASE = "http://localhost:5500"; // Change if deployed

const startBtn    = document.getElementById('start-btn');
const downloadBtn = document.getElementById('download-btn');
const clearBtn    = document.getElementById('clear-btn');
const consoleEl   = document.getElementById('console');
const progressBar = document.getElementById('progress-bar');

function log(msg, anim = "animate__fadeIn") {
  const p = document.createElement('p');
  p.classList.add('animate__animated', anim);
  p.textContent = msg;
  consoleEl.appendChild(p);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function setProgress(p) {
  progressBar.style.width = `${p}%`;
}

clearBtn.onclick = () => {
  consoleEl.innerHTML = "";
  setProgress(0);
  downloadBtn.disabled = true;
};

startBtn.onclick = async () => {
  const url = document.getElementById('url').value;
  const opts = {
    sql:   document.getElementById('sql').checked,
    xss:   document.getElementById('xss').checked,
    ports: document.getElementById('ports').checked,
    tech:  document.getElementById('tech').checked,
    burp:  document.getElementById('burp').checked
  };

  consoleEl.innerHTML = "";
  log(`Initiating scan on ${url}`, "animate__flash");
  setProgress(5);

  try {
    const resp = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ url, attackTypes: Object.keys(opts).filter(k => opts[k]) })
    });

    setProgress(30);

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Server responded with ${resp.status}: ${errText}`);
    }

    const data = await resp.json();

    // Map backend response to frontend expected format
    const discovered = data.urls || [];
    const vulnerabilities = {};
    // Mark SQLi vulnerable URLs
    (data.sql_injection || []).forEach(item => {
      vulnerabilities[item.url] = vulnerabilities[item.url] || {};
      vulnerabilities[item.url].sql = true;
    });
    // Mark XSS vulnerable URLs
    (data.xss || []).forEach(url => {
      vulnerabilities[url] = vulnerabilities[url] || {};
      vulnerabilities[url].xss = true;
    });
    const port_scan = (data.ports || []).map(p => `Port ${p} open`);
    const tech_detect = data.tech || [];
    const burp_logs = data.burp_logs || [];

    for (let i = 0; i < discovered.length; i++) {
      const domain = discovered[i];
      const vs = vulnerabilities[domain] || {};
      let msg = domain;
      if (vs.sql) msg += " — ⚠ SQL";
      if (vs.xss) msg += " — ⚠ XSS";
      log(msg);
      setProgress(30 + ((i+1)/discovered.length)*50);
    }

    if (port_scan.length) {
      log("---- Port Scan ----", "animate__fadeInUp");
      port_scan.forEach(line => log(line, "animate__fadeInUp"));
    }
    if (tech_detect.length) {
      log("---- Tech Detect ----", "animate__fadeInUp");
      tech_detect.forEach(line => log(line, "animate__fadeInUp"));
    }
    if (burp_logs.length) {
      log("---- Burp Logs ----", "animate__fadeInUp");
      burp_logs.forEach(line => log(line, "animate__fadeInUp"));
    }

    setProgress(90);
    downloadBtn.disabled = false;

    downloadBtn.onclick = async () => {
      const blob = await fetch(`${API_BASE}/download-report`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(data)
      }).then(r => r.blob());

      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `report_${Date.now()}.pdf`;
      link.click();
    };

    setProgress(100);

  } catch (error) {
    log(`Request failed: ${error.message}`, "animate__shakeX");
    setProgress(100);
  }
};
