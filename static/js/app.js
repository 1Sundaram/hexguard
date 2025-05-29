const startBtn    = document.getElementById('start-btn');
const downloadBtn = document.getElementById('download-btn');
const clearBtn    = document.getElementById('clear-btn');
const consoleEl   = document.getElementById('console');
const progressBar = document.getElementById('progress-bar');

function log(msg) {
  consoleEl.textContent += msg + "\n";
  consoleEl.scrollTop = consoleEl.scrollHeight;
}
function setProgress(p) {
  progressBar.style.width = p + "%";
}

clearBtn.addEventListener('click', () => {
  consoleEl.textContent = "";
  setProgress(0);
  downloadBtn.disabled = true;
});

startBtn.addEventListener('click', async () => {
  const url = document.getElementById('url').value;
  const opts = {
    sql:   document.getElementById('sql').checked,
    xss:   document.getElementById('xss').checked,
    ports: document.getElementById('ports').checked,
    tech:  document.getElementById('tech').checked,
    burp:  document.getElementById('burp').checked
  };

  log(`Starting scan: ${url}`);
  setProgress(10);

  const resp = await fetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({url, options: opts})
  });
  setProgress(50);

  if (!resp.ok) {
    const err = await resp.json();
    log("Error: " + err.error);
    setProgress(100);
    return;
  }

  const { output, report, vulns } = await resp.json();
  log(output);
  setProgress(80);

  downloadBtn.disabled = false;
  downloadBtn.onclick = async () => {
    const r = await fetch('/api/report', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url, vulns})
    });
    const { report: fname } = await r.json();
    window.open(`/download/${fname}`, '_blank');
  };

  setProgress(100);
});
