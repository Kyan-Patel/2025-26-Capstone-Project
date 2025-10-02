// logs.js — Simulated-only logs feed
// Features: simulated stream, spawn single event, pause/resume, clear, export JSON
// Make sure logs.html includes <div id="sim-log-feed"> and these buttons.

const simFeed = document.getElementById("sim-log-feed");
const btnSimToggle = document.getElementById("btn-toggle-sim");
const btnSpawn = document.getElementById("btn-spawn");
const btnClear = document.getElementById("btn-clear");
const btnExport = document.getElementById("btn-export");

let simInterval = null;
let simPaused = false;
const simHistory = []; // entries: { ts, severity, type: 'sim', text, meta }

// A richer pool of simulated events (varied types & severities)
const sampleEvents = [
  {severity: 'INFO', text: "DHCP OFFER to 192.168.1.14 from gateway (simulated)"},
  {severity: 'INFO', text: "DNS query for library.university.edu from 192.168.1.14 (simulated)"},
  {severity: 'WARN', text: "TLS certificate mismatch observed for 203.0.113.45 (simulated)"},
  {severity: 'WARN', text: "Unauthorized association attempt to SSID 'CampusOpen' from 02:ab:cd:ef:12:34 (simulated)"},
  {severity: 'ALERT', text: "Rogue AP 'FreeCampusWiFi' advertising multiple BSSIDs (simulated)"},
  {severity: 'ALERT', text: "High-risk beacon spam detected from MAC 02:11:22:33:44:55 (simulated)"},
  {severity: 'INFO', text: "ARP probe 192.168.1.99 seen on network (simulated)"},
  {severity: 'INFO', text: "New device joined SSID 'CampusOpen' (192.168.1.77) (simulated)"},
  {severity: 'WARN', text: "Suspicious port scan (multiple SYNs) from 198.51.100.23 (simulated)"},
  {severity: 'INFO', text: "HTTP GET to /login succeeded from 192.168.1.14 (simulated)"},
  {severity: 'ALERT', text: "Potential phishing redirect detected: example.com -> malicious.example (simulated)"},
  {severity: 'INFO', text: "Device 192.168.1.22 responded to mDNS query (simulated)"},
  {severity: 'WARN', text: "Telnet attempt blocked from 192.168.1.50 (simulated)"},
];

// styling helper for severity visuals
function severityStyleElem(elem, severity) {
  if (severity === 'ALERT') {
    elem.style.background = '#ffe6e6';
    elem.style.borderLeft = '6px solid #c62828';
  } else if (severity === 'WARN') {
    elem.style.background = '#fff7e6';
    elem.style.borderLeft = '6px solid #ed6c02';
  } else {
    elem.style.background = '#f4f9ff';
    elem.style.borderLeft = '6px solid #2a5298';
  }
  elem.style.padding = '6px 10px';
  elem.style.borderRadius = '4px';
  elem.style.margin = '6px 0';
  elem.style.fontSize = '0.95em';
}

// append a formatted simulated entry
function appendSimEntry(entry) {
  // entry: { ts, severity, text, meta? }
  const wrapper = document.createElement('div');
  const ts = new Date(entry.ts).toLocaleTimeString();
  wrapper.innerHTML = `<strong>[SIMULATED]</strong> <em>${ts}</em> — <strong>${entry.severity}</strong><div style="margin-top:6px">${entry.text}</div>`;
  severityStyleElem(wrapper, entry.severity);
  // newest on top
  simFeed.prepend(wrapper);
  // cap feed length
  while (simFeed.childElementCount > 300) simFeed.removeChild(simFeed.lastChild);
}

// generate a random simulated event object
function genRandomEvent() {
  const pick = sampleEvents[Math.floor(Math.random() * sampleEvents.length)];
  return {
    ts: Date.now(),
    severity: pick.severity,
    text: pick.text,
    type: 'sim'
  };
}

// push one simulated event to feed & history
function pushSimEvent() {
  const evt = genRandomEvent();
  appendSimEntry(evt);
  simHistory.unshift(evt);
}

// start/stop simulated stream
function startSimStream() {
  if (simInterval) clearInterval(simInterval);
  simInterval = setInterval(() => {
    if (!simPaused) pushSimEvent();
  }, 1200 + Math.floor(Math.random() * 800)); // slight jitter
}

startSimStream();

// UI button handlers
btnSimToggle.addEventListener('click', () => {
  simPaused = !simPaused;
  btnSimToggle.textContent = simPaused ? 'Resume Simulated Stream' : 'Pause Simulated Stream';
});

btnSpawn.addEventListener('click', () => {
  pushSimEvent();
});

btnClear.addEventListener('click', () => {
  simFeed.innerHTML = '';
  simHistory.length = 0;
});

btnExport.addEventListener('click', () => {
  const payload = {
    generatedAt: new Date().toISOString(),
    entries: simHistory.slice(0, 2000)
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `simulated-logs-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

// add an initial banner entry
(function initialNotice() {
  const banner = {
    ts: Date.now(),
    severity: 'INFO',
    text: 'Simulated log stream started — entries are synthetic for demo/testing.',
    type: 'sim'
  };
  simHistory.unshift(banner);
  appendSimEntry(banner);
})();
