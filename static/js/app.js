const API_BASE =
  (window.location.hostname === "localhost" ||
   window.location.hostname === "127.0.0.1")
    ? ""
    : "https://hexguard-api.onrender.com";

const startBtn    = document.getElementById('start-btn');
const downloadBtn = document.getElementById('download-btn');
const clearBtn    = document.getElementById('clear-btn');
const consoleEl   = document.getElementById('console');
const progressBar = document.getElementById('progress-bar');

function log(msg, anim="animate__fadeIn") {
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

  const resp = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({url, options: opts})
  });
  setProgress(30);
  if (!resp.ok) {
    const err = await resp.json();
    log(`Error: ${err.error}`, "animate__shakeX");
    setProgress(100);
    return;
  }

  const {
    discovered, vulnerabilities,
    port_scan, tech_detect, burp_logs
  } = await resp.json();

  // Show each domain one by one
  for (let i = 0; i < discovered.length; i++) {
    const domain = discovered[i];
    await new Promise(r => setTimeout(r, 300)); // brief pause
    const vs = vulnerabilities[domain] || {};
    let msg = domain;
    if (vs.sql) msg += " — ⚠ SQL";
    if (vs.xss) msg += " — ⚠ XSS";
    log(msg);
    setProgress(30 + ((i+1)/discovered.length)*50);
  }

  // then show other sections
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
    const blob = await fetch(`${API_BASE}/api/report`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        url, discovered,
        vulnerabilities, port_scan,
        tech_detect, burp_logs
      })
    }).then(r => r.blob());
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `report_${Date.now()}.pdf`;
    link.click();
  };

  setProgress(100);
};
