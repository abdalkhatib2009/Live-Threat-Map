# app.py
"""
Real-Time Threat Map with Animated Lines, Live Stats, and Bottom Panel
---------------------------------------------------------------------
• Pulls public threat IP feeds (no API key required)
• Geolocates IPs via ip-api.com (free, rate-limited)
• Streams points + attack flows over SSE
• Renders Leaflet world map with animated source→target lines
• Shows live HUD stats (totals, rates, risk split) and a bottom panel table
"""

from __future__ import annotations
import csv, io, json, random, re, threading, time
from collections import deque
from typing import Dict, List

import requests
from cachetools import TTLCache
from flask import Flask, Response, jsonify, render_template_string

app = Flask(__name__)

# -------------------------------
# Config
# -------------------------------
DEV_NAME = "Abdallah Alkhatib"   # ← your credit

REFRESH_SECONDS   = 300          # fetch feeds every 5 minutes
MAX_POINTS        = 1200         # cap markers
BATCH_GEO_LIMIT   = 400          # max attackers geolocated per cycle
SSE_PING_EVERY    = 15           # keep-alive for SSE
GEO_TTL_SECONDS   = 7 * 24 * 3600
FLOW_TTL_SECONDS  = 25           # seconds a flow line remains on map

# Targets (replace with your sensor/public IPs for more realism)
TARGETS = [
    {"ip": "8.8.8.8",   "name": "Google DNS"},
    {"ip": "1.1.1.1",   "name": "Cloudflare DNS"},
    {"ip": "52.216.0.0","name": "AWS Sample"},
]

# Public IP feeds (no API key required)
FEEDS = [
    {"name": "EmergingThreats", "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "parser": "text_ips",  "risk": "compromised-host"},
    {"name": "Blocklist.de",    "url": "https://lists.blocklist.de/lists/all.txt",                         "parser": "text_ips",  "risk": "abusive-source"},
    {"name": "FeodoTracker",    "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",         "parser": "csv_feodo", "risk": "botnet-c2"},
]

IPV4_RE = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# -------------------------------
# In-memory stores
# -------------------------------
points_lock = threading.Lock()
points: deque = deque(maxlen=MAX_POINTS)   # dict: {ip, lat, lon, country, source, risk, first_seen}
flows:  deque = deque(maxlen=2000)         # dict: {src_ip, src_lat, src_lon, dst_ip, dst_lat, dst_lon, ts, risk}

geo_cache = TTLCache(maxsize=20000, ttl=GEO_TTL_SECONDS)

# -------------------------------
# Feed parsers
# -------------------------------
def parse_text_ips(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        l = line.strip()
        if not l or l.startswith("#"):
            continue
        ip = l.split(":")[0]
        if IPV4_RE.match(ip):
            out.append(ip)
    return out

def parse_feodo_csv(text: str) -> List[str]:
    out = []
    f = io.StringIO(text)
    reader = csv.DictReader(f)
    for row in reader:
        ip = (row.get("dst_ip") or row.get("ip") or "").strip()
        if IPV4_RE.match(ip):
            out.append(ip)
    return out

PARSERS = {"text_ips": parse_text_ips, "csv_feodo": parse_feodo_csv}

# -------------------------------
# Geolocation (ip-api.com batch)
# -------------------------------
def geolocate_ips(ips: List[str]) -> Dict[str, dict]:
    unknown = [i for i in ips if i not in geo_cache]
    got = {}
    if not unknown:
        return got
    fields = "status,country,lat,lon,query"
    url = f"http://ip-api.com/batch?fields={fields}"
    for i in range(0, len(unknown), 100):
        chunk = unknown[i:i+100]
        try:
            resp = requests.post(url, json=chunk, timeout=15)
            if resp.status_code == 200:
                for item in resp.json():
                    ip = item.get("query")
                    if item.get("status") == "success" and ip:
                        geo_cache[ip] = {
                            "lat": item.get("lat"),
                            "lon": item.get("lon"),
                            "country": item.get("country"),
                            "ts": time.time(),
                        }
                        got[ip] = geo_cache[ip]
            else:
                time.sleep(2)
        except Exception:
            time.sleep(2)
    return got

# -------------------------------
# Helpers
# -------------------------------
def choose_target_for(ip: str) -> dict:
    """Pick a destination (your monitored target)."""
    t = random.choice(TARGETS)
    if t["ip"] not in geo_cache:
        geolocate_ips([t["ip"]])
    g = geo_cache.get(t["ip"])
    if g:
        return {"ip": t["ip"], "lat": g["lat"], "lon": g["lon"], "name": t.get("name")}
    return {"ip": t["ip"], "lat": None, "lon": None, "name": t.get("name")}

# -------------------------------
# Fetch cycle: builds points + flows
# -------------------------------
def fetch_cycle():
    collected = []
    for feed in FEEDS:
        try:
            r = requests.get(feed["url"], timeout=25)
            if r.status_code != 200 or not r.text:
                continue
            ips = PARSERS[feed["parser"]](r.text)
            sample = ips[-(BATCH_GEO_LIMIT // max(1, len(FEEDS))):]
            for ip in sample:
                collected.append({"ip": ip, "source": feed["name"], "risk": feed["risk"]})
        except Exception:
            continue

    if not collected:
        return

    # Geolocate attackers + targets
    ip_list = list({c["ip"] for c in collected} | {t["ip"] for t in TARGETS})
    geolocate_ips(ip_list)

    now = int(time.time())
    new_points, new_flows = [], []
    for item in collected:
        ip = item["ip"]
        g = geo_cache.get(ip)
        if not g:
            continue
        p = {
            "ip": ip,
            "lat": g["lat"],
            "lon": g["lon"],
            "country": g.get("country"),
            "source": item["source"],
            "risk": item["risk"],
            "first_seen": now,
        }
        new_points.append(p)

        tgt = choose_target_for(ip)
        if tgt["lat"] is None or tgt["lon"] is None:
            continue
        flow = {
            "src_ip": ip,
            "src_lat": p["lat"],
            "src_lon": p["lon"],
            "dst_ip": tgt["ip"],
            "dst_lat": tgt["lat"],
            "dst_lon": tgt["lon"],
            "ts": now,
            "risk": item["risk"],
        }
        new_flows.append(flow)

    with points_lock:
        for pt in new_points:
            points.append(pt)
        for fl in new_flows:
            flows.append(fl)

def background_worker():
    time.sleep(2)
    while True:
        try:
            fetch_cycle()
        except Exception:
            pass
        time.sleep(REFRESH_SECONDS)

threading.Thread(target=background_worker, daemon=True).start()

# -------------------------------
# Web UI (Leaflet + HUD + Panel)
# -------------------------------
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Real-Time Threat Map</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
  <style>
    :root{--bg:#0f172a;--panel:#111827;--border:#1f2937;--text:#e2e8f0;--muted:#93c5fd}
    html, body { height: 100%; margin: 0; background: var(--bg); color: var(--text); font-family: system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,'Helvetica Neue',Arial }
    body { display:flex; flex-direction:column }
    #header { padding: 10px 14px; display:flex; align-items:center; gap:12px; }
    .badge { background:var(--border); color:var(--muted); padding:4px 8px; border-radius:999px; font-size:12px }
    .card { background:var(--panel); border:1px solid var(--border); padding:8px 12px; border-radius:12px }
    a { color:var(--muted) }
    #mapWrap { position:relative; flex: 1 1 auto; min-height: 40vh }
    #map { position:absolute; inset:0 }
    #panel { height: 30vh; border-top:1px solid var(--border); background:var(--panel); display:flex; flex-direction:column }
    #panel header { display:flex; align-items:center; justify-content:space-between; padding:8px 12px; gap:12px; flex-wrap:wrap }
    #tableWrap { overflow:auto; flex: 1 1 auto }
    table { width:100%; border-collapse: collapse; font-size: 13px }
    th, td { padding: 6px 10px; border-bottom: 1px solid var(--border) }
    tr:hover { background:#0b1220; cursor:pointer }
    .legend { position: absolute; bottom: 10px; left: 14px; z-index: 1000; }
    .pill { padding:2px 8px; border-radius:999px; border:1px solid var(--border) }
    #hud { position:absolute; right:14px; top:14px; z-index:1000; display:flex; flex-direction:column; gap:6px }
    .stat { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:6px 10px; font-size:12px }
    .credit { position:absolute; right:14px; bottom:10px; z-index:1000; background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:6px 10px; font-size:12px; opacity:0.9 }
  </style>
</head>
<body>
  <div id="header" class="card">
    <div><strong>Real-Time Threat Map</strong> <span class="badge" id="count">0 points</span></div>
    <div>Sources: EmergingThreats, Blocklist.de, FeodoTracker</div>
    <div class="badge" id="devBadge"></div>
  </div>

  <div id="mapWrap">
    <div id="map"></div>

    <div id="hud">
      <div class="stat" id="totals">Totals: 0 pts • 0 flows</div>
      <div class="stat" id="rates">Rates: 0/min (flows) • 0/5min</div>
      <div class="stat" id="byRisk">Risk: c2 0 • comp 0 • abuse 0</div>
    </div>

    <div class="card legend">
      <div><strong>Risk legend</strong></div>
      <div>• <span class="pill">botnet-c2</span> • <span class="pill">compromised-host</span> • <span class="pill">abusive-source</span></div>
    </div>

    <div class="credit" id="credit"></div>
  </div>

  <section id="panel">
    <header>
      <div style="display:flex;gap:12px;align-items:center">
        <strong>Live Threats</strong> <span class="badge" id="rowCount">0</span>
        <span class="badge" id="flowCount">0 flows</span>
        <span class="badge" id="lastUpdate">—</span>
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <label style="font-size:12px">Show last
          <select id="limitSel" style="background:transparent;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:2px 6px">
            <option>50</option><option selected>100</option><option>200</option><option>400</option>
          </select>
          rows
        </label>
        <label style="font-size:12px">Filter risk
          <select id="riskSel" style="background:transparent;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:2px 6px">
            <option value="all" selected>All</option>
            <option value="botnet-c2">botnet-c2</option>
            <option value="compromised-host">compromised-host</option>
            <option value="abusive-source">abusive-source</option>
          </select>
        </label>
      </div>
    </header>
    <div id="tableWrap">
      <table id="tbl">
        <thead>
          <tr><th>IP</th><th>Country</th><th>Risk</th><th>Source</th><th>First Seen</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/leaflet-ant-path/dist/leaflet-ant-path.min.js"></script>
  <script>
    // Developer credit (injected from server)
    document.getElementById('devBadge').textContent = 'Developer: ' + {{ dev_name_json }};
    document.getElementById('credit').textContent  = 'Built by ' + {{ dev_name_json }};

    const map = L.map('map', { worldCopyJump: true }).setView([20, 10], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '© OpenStreetMap contributors' }).addTo(map);

    const markers = {};      // ip -> marker
    const rows = [];         // threat points for panel
    const flowEvents = [];   // flows for stats
    const flowsOnMap = [];   // for cleanup

    function riskColor(risk){
      if (risk === 'botnet-c2') return '#ef4444';
      if (risk === 'compromised-host') return '#f59e0b';
      if (risk === 'abusive-source') return '#3b82f6';
      return '#22c55e';
    }

    function addPoint(p){
      if (!p) return;
      if (!markers[p.ip]) {
        const icon = L.divIcon({ className:'', html:`<div style="width:12px;height:12px;border-radius:50%;background:${riskColor(p.risk)};box-shadow:0 0 12px ${riskColor(p.risk)}88"></div>` });
        const m = L.marker([p.lat,p.lon], { icon }).addTo(map);
        m.bindPopup(`<b>${p.ip}</b><br/>${p.country||''}<br/><small>${p.source} • ${p.risk}</small>`);
        markers[p.ip] = m;
        document.getElementById('count').textContent = Object.keys(markers).length + ' points';
      }
      rows.push(p);
      renderPanel();
      updateStatsHUD();
    }

    function drawFlow(f){
      try{
        const latlngs = [[f.src_lat,f.src_lon],[f.dst_lat,f.dst_lon]];
        const ant = L.polyline.antPath(latlngs, { "paused": false, "reverse": false, "delay": 400, "dashArray": [10,20], "weight": 3, "opacity": 0.9, "color": riskColor(f.risk) });
        ant.addTo(map);
        flowsOnMap.push({obj: ant, ts: f.ts});
        flowEvents.push({ts: f.ts, risk: f.risk});
        const p = L.circleMarker([f.dst_lat,f.dst_lon], {radius:6, weight:1, opacity:0.95}).addTo(map);
        setTimeout(()=>{ try{ map.removeLayer(p);}catch(e){} }, 12000);
        updateStatsHUD();
      }catch(e){}
    }

    // periodic cleanup of expired flows on map
    setInterval(()=>{
      const cutoff = Math.floor(Date.now()/1000) - {{ flow_ttl }};
      while(flowsOnMap.length && flowsOnMap[0].ts < cutoff){
        try{ map.removeLayer(flowsOnMap[0].obj); }catch(e){}
        flowsOnMap.shift();
      }
    }, 3000);

    function renderPanel(){
      const limit = parseInt(document.getElementById('limitSel').value,10) || 100;
      const riskFilter = document.getElementById('riskSel').value;
      const tbody = document.querySelector('#tbl tbody');
      let data = rows;
      if (riskFilter !== 'all') data = data.filter(r => r.risk === riskFilter);
      const slice = data.slice(-limit).reverse();
      tbody.innerHTML = slice.map(r => `
        <tr data-ip="${r.ip}">
          <td><span style="color:${riskColor(r.risk)}">●</span> ${r.ip}</td>
          <td>${r.country || ''}</td>
          <td>${r.risk}</td>
          <td>${r.source}</td>
          <td>${fmtTime(r.first_seen)}</td>
        </tr>`).join('');
      document.getElementById('rowCount').textContent = slice.length;
      document.getElementById('flowCount').textContent = flowEvents.length + ' flows';
      document.getElementById('lastUpdate').textContent = slice.length ? ('Updated ' + new Date().toLocaleTimeString()) : '—';
      tbody.querySelectorAll('tr').forEach(tr => {
        tr.onclick = () => {
          const ip = tr.getAttribute('data-ip'); const m = markers[ip];
          if (m) { map.flyTo(m.getLatLng(), 4, {duration:0.6}); m.openPopup(); }
        };
      });
    }

    function updateStatsHUD(){
      const totalsEl = document.getElementById('totals');
      totalsEl.textContent = `Totals: ${rows.length} pts • ${flowEvents.length} flows`;
      const now = Math.floor(Date.now()/1000);
      const perMin = flowEvents.filter(f => now - f.ts <= 60).length;
      const per5   = flowEvents.filter(f => now - f.ts <= 300).length;
      document.getElementById('rates').textContent = `Rates: ${perMin}/min (flows) • ${per5}/5min`;
      const c2 = rows.filter(r=>r.risk==='botnet-c2').length;
      const ch = rows.filter(r=>r.risk==='compromised-host').length;
      const ab = rows.filter(r=>r.risk==='abusive-source').length;
      document.getElementById('byRisk').textContent = `Risk: c2 ${c2} • comp ${ch} • abuse ${ab}`;
    }

    function fmtTime(ts){ if(!ts) return ''; const d = new Date(ts*1000); return d.toISOString().replace('T',' ').substring(0,19); }

    // Initial load
    fetch('/data').then(r => r.json()).then(obj => {
      obj.points.forEach(addPoint);
      obj.flows.forEach(drawFlow);
      updateStatsHUD();
    });

    // Live updates via SSE
    const es = new EventSource('/stream');
    es.onmessage = (ev) => {
      try {
        const payload = JSON.parse(ev.data);
        if (payload.points) payload.points.forEach(addPoint);
        if (payload.flows)  payload.flows.forEach(drawFlow);
        renderPanel();
        updateStatsHUD();
      } catch (e) {}
    };

    document.getElementById('limitSel').addEventListener('change', ()=>{ renderPanel(); updateStatsHUD(); });
    document.getElementById('riskSel').addEventListener('change',  ()=>{ renderPanel(); updateStatsHUD(); });
  </script>
</body>
</html>
"""

# -------------------------------
# Routes
# -------------------------------
@app.route("/")
def index():
    html = INDEX_HTML.replace("{{ flow_ttl }}", str(FLOW_TTL_SECONDS))
    html = html.replace("{{ dev_name_json }}", json.dumps(DEV_NAME))
    return render_template_string(html)

@app.route("/data")
def data():
    with points_lock:
        return jsonify({"points": list(points), "flows": list(flows)})

@app.route("/stream")
def stream():
    def event_stream(last_idx=[0,0]):
        # last_idx[0] -> points length sent, last_idx[1] -> flows length sent
        yield "event: ping\n" + f"data: {int(time.time())}\n\n"
        while True:
            time.sleep(1)
            payload = {}
            with points_lock:
                if last_idx[0] < len(points):
                    payload["points"] = list(points)[last_idx[0]:]
                    last_idx[0] = len(points)
                if last_idx[1] < len(flows):
                    payload["flows"] = list(flows)[last_idx[1]:]
                    last_idx[1] = len(flows)
            if payload:
                yield "data: " + json.dumps(payload) + "\n\n"
            else:
                yield "event: ping\n" + f"data: {int(time.time())}\n\n"
                time.sleep(SSE_PING_EVERY)
    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/healthz")
def healthz():
    return {"ok": True, "points": len(points), "flows": len(flows), "cache_size": len(geo_cache)}

if __name__ == "__main__":
    # warm up targets and kick a first fetch
    threading.Thread(target=lambda: geolocate_ips([t["ip"] for t in TARGETS]), daemon=True).start()
    threading.Thread(target=fetch_cycle, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=True)
