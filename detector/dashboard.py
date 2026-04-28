"""
dashboard.py

Implements a Flask-based web dashboard to visualize real-time anomaly detection metrics.
Provides a self-contained HTML UI and a JSON API endpoint. The dashboard runs in its own
daemon thread to avoid blocking the main packet processing loop.
"""

import threading
import time
import json
import logging
import psutil
from datetime import datetime, timezone
import yaml
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HNG Anomaly Detector</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --primary: #58a6ff;
            --danger: #f85149;
            --success: #3fb950;
            --warning: #d29922;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --font-mono: 'Courier New', Courier, monospace;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
        }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: var(--font-sans);
            margin: 0;
            padding: 0;
            line-height: 1.5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        #error-banner {
            display: none;
            background-color: var(--danger);
            color: white;
            text-align: center;
            padding: 10px;
            font-weight: bold;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        h1 {
            color: var(--primary);
            margin: 0 0 5px 0;
        }
        .subtitle {
            color: var(--text-muted);
            font-size: 0.9em;
            margin: 0;
        }
        .uptime {
            font-family: var(--font-mono);
            color: var(--success);
            font-weight: bold;
        }
        .grid-4 {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 15px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .card-title {
            color: var(--text-muted);
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 10px;
        }
        .card-value {
            font-family: var(--font-mono);
            font-size: 1.8em;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }
        th, td {
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid var(--border);
        }
        th {
            color: var(--text-muted);
            font-weight: normal;
        }
        td.mono {
            font-family: var(--font-mono);
        }
        .badge {
            padding: 2px 6px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            color: #fff;
        }
        .badge-danger { background-color: var(--danger); }
        .badge-success { background-color: var(--success); }
        .badge-warning { background-color: var(--warning); }
        .badge-primary { background-color: var(--primary); }
        
        .progress-bg {
            background-color: var(--border);
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 5px;
        }
        .progress-bar {
            height: 100%;
            transition: width 0.3s ease, background-color 0.3s ease;
        }
        
        .section-title {
            color: var(--primary);
            border-bottom: 1px solid var(--border);
            padding-bottom: 5px;
            margin-top: 30px;
            margin-bottom: 15px;
        }
        
        footer {
            margin-top: 40px;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8em;
            border-top: 1px solid var(--border);
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <div id="error-banner">⚠ Connection lost — retrying...</div>
    <div class="container">
        <header>
            <div>
                <h1>HNG Anomaly Detector</h1>
                <p class="subtitle">cloud.ng — Live Security Dashboard</p>
            </div>
            <div class="uptime" id="uptime">0h 0m 0s</div>
        </header>

        <div class="grid-4">
            <div class="card">
                <div class="card-title">Global Req/s</div>
                <div class="card-value" id="global-rps">0.00</div>
            </div>
            <div class="card">
                <div class="card-title">Banned IPs</div>
                <div class="card-value" id="banned-count">0</div>
            </div>
            <div class="card">
                <div class="card-title">CPU %</div>
                <div class="card-value" id="cpu-val">0.0%</div>
                <div class="progress-bg"><div class="progress-bar" id="cpu-bar" style="width: 0%; background-color: var(--success)"></div></div>
            </div>
            <div class="card">
                <div class="card-title">Memory %</div>
                <div class="card-value" id="mem-val">0.0%</div>
                <div class="progress-bg"><div class="progress-bar" id="mem-bar" style="width: 0%; background-color: var(--success)"></div></div>
            </div>
        </div>

        <h3 class="section-title">Learned Baseline</h3>
        <div class="grid-2">
            <div class="card">
                <div class="card-title">Effective Mean</div>
                <div class="card-value" id="eff-mean">0.00</div>
            </div>
            <div class="card">
                <div class="card-title">Effective Stddev</div>
                <div class="card-value" id="eff-stddev">0.00</div>
            </div>
        </div>

        <h3 class="section-title">Banned IPs</h3>
        <div class="card" style="padding: 0;">
            <table id="banned-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Banned At</th>
                        <th>Ban #</th>
                        <th>Duration</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted)">No IPs currently banned</td></tr>
                </tbody>
            </table>
        </div>

        <h3 class="section-title">Top 10 Source IPs</h3>
        <div class="card" style="padding: 0;">
            <table id="top10-table">
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>IP Address</th>
                        <th>Req/s</th>
                        <th>Threat Level</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>

        <footer>
            HNG Anomaly Detector | Protecting cloud.ng | Last updated: <span id="last-updated">-</span>
        </footer>
    </div>

    <script>
        function formatUptime(seconds) {
            const h = Math.floor(seconds / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            const s = Math.floor(seconds % 60);
            return `${h}h ${m}m ${s}s`;
        }

        function getColorForPercent(pct) {
            if (pct > 80) return 'var(--danger)';
            if (pct > 60) return 'var(--warning)';
            return 'var(--success)';
        }
        
        function updateDashboard() {
            fetch('/api/metrics')
                .then(response => {
                    if (!response.ok) throw new Error('Network response was not ok');
                    return response.json();
                })
                .then(data => {
                    document.getElementById('error-banner').style.display = 'none';
                    
                    document.getElementById('uptime').innerText = formatUptime(data.uptime_seconds);
                    document.getElementById('global-rps').innerText = data.global_rps.toFixed(2);
                    document.getElementById('banned-count').innerText = data.banned_ips.length;
                    
                    document.getElementById('cpu-val').innerText = data.cpu_percent.toFixed(1) + '%';
                    const cpuBar = document.getElementById('cpu-bar');
                    cpuBar.style.width = data.cpu_percent + '%';
                    cpuBar.style.backgroundColor = getColorForPercent(data.cpu_percent);

                    document.getElementById('mem-val').innerText = data.memory_percent.toFixed(1) + '%';
                    const memBar = document.getElementById('mem-bar');
                    memBar.style.width = data.memory_percent + '%';
                    memBar.style.backgroundColor = getColorForPercent(data.memory_percent);

                    document.getElementById('eff-mean').innerText = data.effective_mean.toFixed(2);
                    document.getElementById('eff-stddev').innerText = data.effective_stddev.toFixed(2);
                    
                    document.getElementById('last-updated').innerText = new Date(data.timestamp).toLocaleTimeString();

                    // Update Banned Table
                    const banTbody = document.querySelector('#banned-table tbody');
                    if (data.banned_ips.length === 0) {
                        banTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted)">No IPs currently banned</td></tr>';
                    } else {
                        banTbody.innerHTML = data.banned_ips.map(ip => {
                            const isPerm = ip.duration_minutes === null || ip.duration_minutes === "Infinity" || ip.ban_count >= 4;
                            const statusHtml = isPerm ? 
                                '<span class="badge badge-success">PERMANENT</span>' : 
                                '<span class="badge badge-danger">BANNED</span>';
                                
                            const durStr = ip.duration_minutes === null || ip.duration_minutes === "Infinity" ? "Permanent" : `${ip.duration_minutes} min`;
                            const timeStr = new Date(ip.banned_at).toLocaleTimeString();
                            
                            return `<tr>
                                <td class="mono">${ip.ip}</td>
                                <td>${timeStr}</td>
                                <td>${ip.ban_count}</td>
                                <td>${durStr}</td>
                                <td>${statusHtml}</td>
                            </tr>`;
                        }).join('');
                    }

                    // Update Top 10
                    const topTbody = document.querySelector('#top10-table tbody');
                    topTbody.innerHTML = data.top_10_ips.map((ip, i) => {
                        let threatHtml = '<span class="badge badge-success">NORMAL</span>';
                        if (ip.rps > 3 * data.effective_mean) {
                            threatHtml = '<span class="badge badge-danger">HIGH</span>';
                        } else if (ip.rps > data.effective_mean) {
                            threatHtml = '<span class="badge badge-warning">ELEVATED</span>';
                        }
                        
                        return `<tr>
                            <td>${i + 1}</td>
                            <td class="mono">${ip.ip}</td>
                            <td class="mono">${ip.rps.toFixed(2)}</td>
                            <td>${threatHtml}</td>
                        </tr>`;
                    }).join('');
                })
                .catch(err => {
                    console.error('Fetch error:', err);
                    document.getElementById('error-banner').style.display = 'block';
                });
        }

        updateDashboard();
        setInterval(updateDashboard, 3000);
    </script>
</body>
</html>
"""

class Dashboard:
    def __init__(self, blocker, baseline_tracker, detector, start_time: float, config_path: str = "/home/ubuntu/hng-detector/detector/config.yaml"):
        self.blocker = blocker
        self.tracker = baseline_tracker
        self.detector = detector
        self.start_time = start_time
        
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.port = self.config.get('dashboard_port', 8080)
        self.refresh_seconds = self.config.get('dashboard_refresh_seconds', 3)
        
        # Initialize Flask app
        self.app = Flask(__name__)
        
        @self.app.route('/')
        def index():
            # Serves the full self-contained HTML page
            return render_template_string(HTML_TEMPLATE)
            
        @self.app.route('/api/metrics')
        def metrics():
            now = time.time()
            iso_now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            
            # Aggregate Banned IPs from blocker memory dict
            banned_dict = self.blocker.get_banned_ips()
            banned_list = []
            for ip, info in banned_dict.items():
                if info.get('active', False):
                    banned_at_iso = datetime.utcfromtimestamp(info.get('banned_at', 0)).strftime('%Y-%m-%dT%H:%M:%SZ')
                    dur = info.get('duration_minutes')
                    if dur == float('inf'):
                        dur = "Infinity"
                    banned_list.append({
                        "ip": ip,
                        "banned_at": banned_at_iso,
                        "ban_count": info.get('ban_count', 1),
                        "duration_minutes": dur
                    })
                    
            # Aggregate Top 10 Source IPs
            # Iterate detector.ip_windows, compute rps = len(deque) / 60 for each IP
            ip_rates = []
            # Wrap in list to avoid dict modification errors during iteration
            for ip, window in list(self.detector.ip_windows.items()):
                rps = len(window) / 60.0
                if rps > 0:
                    ip_rates.append({"ip": ip, "rps": rps})
            
            ip_rates.sort(key=lambda x: x['rps'], reverse=True)
            top_10 = ip_rates[:10]
            
            # Retrieve baseline statistics
            global_rps = self.tracker.get_global_rps(now)
            mean, stddev, _, _ = self.tracker.get_baseline()
            
            cpu_pct = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            mem_pct = mem.percent
            
            uptime = int(now - self.start_time)
            
            payload = {
                "banned_ips": banned_list,
                "global_rps": global_rps,
                "top_10_ips": top_10,
                "cpu_percent": cpu_pct,
                "memory_percent": mem_pct,
                "effective_mean": mean,
                "effective_stddev": stddev,
                "uptime_seconds": uptime,
                "timestamp": iso_now
            }
            
            return jsonify(payload)

    def start(self) -> None:
        """Starts the Flask application in a daemon thread to prevent blocking."""
        thread = threading.Thread(
            target=lambda: self.app.run(
                host="0.0.0.0",
                port=self.port,
                threaded=True,
                use_reloader=False,
                debug=False
            ),
            daemon=True
        )
        thread.start()
        logger.info(f"Dashboard started on port {self.port}")
