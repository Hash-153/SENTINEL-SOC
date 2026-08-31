"""Zero-dependency HTTP Web Dashboard Server for Sentinel SIEM & NIDS."""

import http.server
import json
import socketserver
import threading
import time
import urllib.parse
from typing import Optional
from sentinel.daemon.service import SentinelService
from sentinel.capture.synthetic_generator import SyntheticAttackGenerator

HTML_DASHBOARD_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel NIDS & SIEM - Security Operations Center</title>
    <style>
        :root {
            --bg-primary: #0a0f1d;
            --bg-secondary: #11192e;
            --bg-card: #17223b;
            --border-color: #223456;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --sev-critical: #ef4444;
            --sev-high: #f97316;
            --sev-medium: #eab308;
            --sev-low: #3b82f6;
            --sev-info: #64748b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background: var(--bg-primary); color: var(--text-main); line-height: 1.5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        
        /* Header */
        .navbar { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 12px; margin-bottom: 24px; }
        .logo-group { display: flex; align-items: center; gap: 14px; }
        .logo-icon { width: 38px; height: 38px; background: linear-gradient(135deg, #06b6d4, #3b82f6); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 20px; color: #fff; }
        .logo-title { font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }
        .logo-badge { font-size: 11px; background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan); padding: 3px 8px; border-radius: 12px; border: 1px solid rgba(6, 182, 212, 0.3); font-weight: 600; }
        .nav-actions { display: flex; gap: 12px; }
        .btn { padding: 8px 16px; border-radius: 8px; border: none; font-weight: 600; font-size: 13px; cursor: pointer; transition: all 0.2s; display: inline-flex; align-items: center; gap: 8px; }
        .btn-primary { background: linear-gradient(135deg, #06b6d4, #2563eb); color: #fff; }
        .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn-secondary { background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border-color); }
        .btn-secondary:hover { background: #1e2c4a; }
        
        /* Metrics Grid */
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .metric-card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; }
        .metric-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; margin-bottom: 8px; }
        .metric-value { font-size: 32px; font-weight: 800; color: #fff; }
        .metric-sub { font-size: 12px; color: var(--accent-cyan); margin-top: 4px; }

        /* Main Content Layout */
        .dashboard-layout { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
        @media (max-width: 1024px) { .dashboard-layout { grid-template-columns: 1fr; } }
        
        .card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; margin-bottom: 24px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 12px; }
        .card-title { font-size: 16px; font-weight: 700; color: #fff; }
        
        /* Tables & Lists */
        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
        th { color: var(--text-muted); font-weight: 600; padding: 10px 12px; border-bottom: 1px solid var(--border-color); }
        td { padding: 12px; border-bottom: 1px solid rgba(34, 52, 86, 0.5); }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }
        
        /* Badges */
        .badge { padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .badge-CRITICAL { background: rgba(239, 68, 68, 0.15); color: var(--sev-critical); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-HIGH { background: rgba(249, 115, 22, 0.15); color: var(--sev-high); border: 1px solid rgba(249, 115, 22, 0.3); }
        .badge-MEDIUM { background: rgba(234, 179, 8, 0.15); color: var(--sev-medium); border: 1px solid rgba(234, 179, 8, 0.3); }
        .badge-LOW { background: rgba(59, 130, 246, 0.15); color: var(--sev-low); border: 1px solid rgba(59, 130, 246, 0.3); }
        .badge-INFO { background: rgba(100, 116, 139, 0.15); color: var(--sev-info); border: 1px solid rgba(100, 116, 139, 0.3); }

        .tag { font-family: monospace; background: var(--bg-card); padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #38bdf8; }
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #22c55e; margin-right: 6px; }
        .status-dot.active { animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }

        .category-bar-item { margin-bottom: 12px; }
        .category-bar-label { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; }
        .category-bar-track { height: 6px; background: var(--bg-card); border-radius: 3px; overflow: hidden; }
        .category-bar-fill { height: 100%; background: linear-gradient(90deg, #06b6d4, #3b82f6); border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <header class="navbar">
            <div class="logo-group">
                <div class="logo-icon">S</div>
                <div>
                    <div class="logo-title">SENTINEL SOC</div>
                    <span class="logo-badge">NIDS & SIEM ENTERPRISE v1.0.0</span>
                </div>
            </div>
            <div class="nav-actions">
                <span style="display: flex; align-items: center; font-size: 13px; margin-right: 12px; color: #22c55e;">
                    <span class="status-dot active"></span> LIVE SENSORS ACTIVE
                </span>
                <button class="btn btn-secondary" onclick="fetchDashboardData()">↻ Refresh</button>
                <button class="btn btn-primary" onclick="triggerDrill()">⚡ Run Attack Drill</button>
            </div>
        </header>

        <!-- Metric Counters -->
        <section class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Security Events</div>
                <div class="metric-value" id="val-events">0</div>
                <div class="metric-sub">Captured & Parsed</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Correlated Incidents</div>
                <div class="metric-value" id="val-incidents" style="color: #ef4444;">0</div>
                <div class="metric-sub">Multi-Stage Attacks</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Critical / High Threats</div>
                <div class="metric-value" id="val-critical" style="color: #f97316;">0</div>
                <div class="metric-sub">Immediate Action Required</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Top Active Adversaries</div>
                <div class="metric-value" id="val-attackers">0</div>
                <div class="metric-sub">Source IPs Tracked</div>
            </div>
        </section>

        <div class="dashboard-layout">
            <!-- Left Column: Incidents & Live Alert Feed -->
            <div>
                <!-- Synthesized Incidents Card -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🔥 High-Priority Correlated Incidents (CEP Engine)</div>
                    </div>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Incident Title</th>
                                    <th>Attacker IP</th>
                                    <th>Target Hosts</th>
                                    <th>Events</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody id="incidents-body">
                                <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No active incidents. Click "Run Attack Drill" to simulate threats.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Live Security Events Feed -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🛡️ Real-Time Security Event Stream</div>
                    </div>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Severity</th>
                                    <th>Category</th>
                                    <th>Source -> Destination</th>
                                    <th>Rule / Details</th>
                                </tr>
                            </thead>
                            <tbody id="events-body">
                                <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Waiting for packet ingestion...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Right Column: Threat Stats & Intelligence -->
            <div>
                <!-- Attack Category Breakdown -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">📊 Attack Vector Distribution</div>
                    </div>
                    <div id="category-bars">
                        <p style="color: var(--text-muted); font-size: 13px;">No data collected yet.</p>
                    </div>
                </div>

                <!-- Top Threat Source IPs -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🎯 Top Adversary IP Addresses</div>
                    </div>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Attacker IP</th>
                                    <th>Events</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="attackers-body">
                                <tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No threat sources detected.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Engine Specifications -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">⚙️ Engine Status</div>
                    </div>
                    <div style="font-size: 13px; color: var(--text-muted);">
                        <p style="margin-bottom: 6px;"><strong>Database:</strong> SQLite WAL Mode</p>
                        <p style="margin-bottom: 6px;"><strong>Dissectors:</strong> Ethernet, IPv4, TCP, UDP, DNS, TLS, HTTP</p>
                        <p style="margin-bottom: 6px;"><strong>Threat Intelligence:</strong> MITRE ATT&CK, CVE Knowledgebase</p>
                        <p style="margin-bottom: 6px;"><strong>Compliance:</strong> NIST 800-53, PCI-DSS v4.0, CIS v8</p>
                        <p><strong>Licensing:</strong> Proprietary (Zero 3rd-Party Packages)</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function fetchDashboardData() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                // Update Metrics
                document.getElementById('val-events').textContent = data.stats.total_events || 0;
                document.getElementById('val-incidents').textContent = data.stats.total_incidents || 0;
                
                const crit = (data.stats.events_by_severity.CRITICAL || 0) + (data.stats.events_by_severity.HIGH || 0);
                document.getElementById('val-critical').textContent = crit;
                document.getElementById('val-attackers').textContent = Object.keys(data.stats.top_attackers || {}).length;

                // Update Incidents Table
                const incTbody = document.getElementById('incidents-body');
                if (data.incidents && data.incidents.length > 0) {
                    incTbody.innerHTML = data.incidents.map(inc => `
                        <tr>
                            <td><span class="badge badge-${inc.severity}">${inc.severity}</span></td>
                            <td><strong>${inc.title}</strong><div style="font-size: 11px; color: var(--text-muted);">${inc.summary}</div></td>
                            <td><span class="tag">${inc.src_ip || 'N/A'}</span></td>
                            <td><span class="tag">${inc.target_ips_json || '[]'}</span></td>
                            <td><strong>${inc.event_count}</strong></td>
                            <td><span style="color: #22c55e; font-weight: 600;">● ${inc.status}</span></td>
                        </tr>
                    `).join('');
                } else {
                    incTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No active incidents.</td></tr>';
                }

                // Update Events Table
                const evTbody = document.getElementById('events-body');
                if (data.events && data.events.length > 0) {
                    evTbody.innerHTML = data.events.slice(0, 15).map(ev => {
                        const d = new Date(ev.timestamp * 1000);
                        const timeStr = d.toTimeString().split(' ')[0];
                        return `
                            <tr>
                                <td style="color: var(--text-muted);">${timeStr}</td>
                                <td><span class="badge badge-${ev.severity}">${ev.severity}</span></td>
                                <td><span class="tag">${ev.category}</span></td>
                                <td>${ev.src_ip}:${ev.src_port || 0} -> ${ev.dst_ip}:${ev.dst_port || 0} (${ev.protocol})</td>
                                <td><strong>${ev.title}</strong><div style="font-size: 11px; color: var(--text-muted);">${ev.description}</div></td>
                            </tr>
                        `;
                    }).join('');
                }

                // Update Attack Vector Breakdown
                const catContainer = document.getElementById('category-bars');
                const total = data.stats.total_events || 1;
                const cats = data.stats.events_by_category || {};
                if (Object.keys(cats).length > 0) {
                    catContainer.innerHTML = Object.entries(cats).map(([cat, count]) => {
                        const pct = Math.round((count / total) * 100);
                        return `
                            <div class="category-bar-item">
                                <div class="category-bar-label">
                                    <span>${cat}</span>
                                    <span><strong>${count}</strong> (${pct}%)</span>
                                </div>
                                <div class="category-bar-track">
                                    <div class="category-bar-fill" style="width: ${pct}%;"></div>
                                </div>
                            </div>
                        `;
                    }).join('');
                }

                // Update Top Attackers
                const atkBody = document.getElementById('attackers-body');
                const atks = data.stats.top_attackers || {};
                if (Object.keys(atks).length > 0) {
                    atkBody.innerHTML = Object.entries(atks).map(([ip, count]) => `
                        <tr>
                            <td><span class="tag" style="color: #ef4444;">${ip}</span></td>
                            <td><strong>${count}</strong> hits</td>
                            <td><span class="badge badge-HIGH">TRACKING</span></td>
                        </tr>
                    `).join('');
                }
            } catch (err) {
                console.error("Dashboard fetch error:", err);
            }
        }

        async function triggerDrill() {
            try {
                await fetch('/api/simulate', { method: 'POST' });
                setTimeout(fetchDashboardData, 800);
            } catch (err) {
                alert("Drill request failed: " + err);
            }
        }

        // Initial Load & Interval
        fetchDashboardData();
        setInterval(fetchDashboardData, 2000);
    </script>
</body>
</html>
"""


class DashboardRequestHandler(http.server.BaseHTTPRequestHandler):
    service: SentinelService

    def log_message(self, format, *args):
        # Silence default HTTP access logs for clean console
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD_TEMPLATE.encode("utf-8"))
        elif parsed.path == "/api/stats":
            self.service.event_repo.flush()
            stats = self.service.event_repo.get_stats()
            events = self.service.event_repo.get_recent_events(limit=30)
            incidents = self.service.event_repo.get_incidents(limit=10)

            payload = {
                "stats": stats,
                "events": events,
                "incidents": incidents,
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/simulate":
            # Run synthetic multi-vector drill
            for p in SyntheticAttackGenerator.generate_port_scan_packets():
                self.service.ingest_packet(p)
            self.service.ingest_packet(SyntheticAttackGenerator.generate_stealth_xmas_scan())
            self.service.ingest_packet(SyntheticAttackGenerator.generate_sqli_packet())
            self.service.ingest_packet(SyntheticAttackGenerator.generate_directory_traversal_packet())
            self.service.ingest_packet(SyntheticAttackGenerator.generate_cmd_injection_packet())
            self.service.ingest_packet(SyntheticAttackGenerator.generate_dns_tunneling_packet())
            self.service.ingest_packet(SyntheticAttackGenerator.generate_high_entropy_packet())
            for p in SyntheticAttackGenerator.generate_multi_stage_campaign():
                self.service.ingest_packet(p)

            time.sleep(0.5)
            self.service.event_repo.flush()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "SUCCESS", "message": "Drill launched"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


class DashboardServer:
    """Embedded zero-dependency HTTP server hosting Sentinel SOC Web UI."""

    def __init__(self, service: SentinelService, host: str = "127.0.0.1", port: int = 8080) -> None:
        self.service = service
        self.host = host
        self.port = port
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = DashboardRequestHandler
        handler.service = self.service

        # Attempt binding to port with fallback
        for p in [self.port, 8081, 8082, 8888]:
            try:
                self.port = p
                self._server = http.server.HTTPServer((self.host, self.port), handler)
                break
            except OSError:
                continue

        if not self._server:
            raise RuntimeError(f"Could not bind HTTP dashboard to {self.host}:{self.port}")

        self._thread = threading.Thread(target=self._server.serve_forever, name="DashboardServerThread", daemon=True)
        self._thread.start()
        print(f"\n[+] Sentinel SOC Web Dashboard live at: http://{self.host}:{self.port}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
