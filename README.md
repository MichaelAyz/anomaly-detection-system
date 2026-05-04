# Anomaly Detection System

This project is a real-time HTTP traffic anomaly detection engine that watches Nginx access logs, learns normal traffic patterns, detects attacks using statistical methods, blocks malicious IPs via iptables, and sends Slack alerts. Built for cloud.ng, it is designed to run securely alongside a Nextcloud Docker deployment to protect the publicly accessible cloud storage platform from aggressive anomalies and traffic spikes.

## Live Deployment

* **Server IP:** 100.26.113.199
* **Metrics Dashboard:** http://yzmetrics.duckdns.org:8080
* **Nextcloud:** accessible via IP only at http://100.26.113.199

## Language Choice

This system is built entirely in **Python**. Python was chosen for rapid development and iteration without the overhead of a compilation step, which is critical under tight time pressures. The robust standard library provides excellent support for multithreading and subprocess management (required for `iptables` execution). It also enables clean generator patterns for real-time log tailing and straightforward memory management using `collections.deque`. System-level metrics are efficiently gathered using `psutil`.

## Architecture

The entire stack is designed for resilience and zero-interference with the core application:

1. **Nginx reverse proxy (Docker)** → Writes structured JSON access logs to a named Docker volume (`HNG-nginx-logs`).
2. **Nextcloud (Docker)** → Mounts the volume read-only and serves the core application.
3. **HNG Detector daemon (systemd service on host)** → Runs directly on the host machine, reads the Docker volume directly, executes the statistical detection logic, manages `iptables` blocking rules, and serves the metrics dashboard natively on port 8080.

Reference the architecture diagram: `docs/architecture.png`

## How the Sliding Window Works

The detection engine uses pure sliding windows to maintain absolute precision without relying on rigid per-minute buckets or arbitrary rate-limiting libraries.

* **Two `collections.deque` structures** — one global, and one per-IP — store the exact timestamps of every request seen in the last 60 seconds.
* On every incoming log line, the current timestamp is appended to both deques.
* Before every rate calculation, entries older than `now - 60` are evicted from the left of the deque using a rapid while loop: `while deque and deque[0] < now - 60: deque.popleft()`
* The current rate is calculated dynamically: `Current rate = len(deque) / 60`
* The system utilizes no counters and no dicts for rate accumulation — just pure timestamp deques.
* Per-IP deques live in a thread-safe `defaultdict(deque)` keyed by source IP.

## How the Baseline Works

The system learns normal traffic patterns over time to establish a dynamic baseline:

* A rolling deque of per-second request counts covers the last 30 minutes (1800 entries max).
* Every second, the current second's request count is appended.
* Every 60 seconds, `recalculate()` evicts entries older than 30 minutes, then computes the `mean` and `stddev` from the remaining counts using `statistics.mean()` and `statistics.stdev()`.
* **Per-hour slots:** A dictionary keyed by the hour integer stores per-second RPS values. When the current hour has ≥ 10 samples, the baseline prefers that slot over the full rolling window for higher relevance and accuracy.
* **Floor value:** The `effective_mean` is never allowed to drop below `0.1 rps`. This prevents division-by-zero errors and avoids false positives during completely idle periods.
* The baseline is never hardcoded — it always reflects actual observed traffic.

## How Detection Works

Detection runs asynchronously on every parsed request:

* Every parsed log line triggers a check in `detector.py`.
* A statistical Z-score is computed: `(current_rps - baseline_mean) / baseline_stddev`.
* An IP is flagged as anomalous if the **z-score exceeds 3.0** OR the **rate exceeds 5x the baseline mean** — whichever fires first.
* **Error surge:** If an IP's 4xx/5xx error rate exceeds 3x the baseline error rate, the thresholds dynamically tighten to a z-score of `2.0` and a `3x` multiplier.
* A **Global anomaly** uses the same calculation on the global request rate. It triggers a high-priority Slack alert only, without executing a global IP block to prevent self-denial of service.
* All thresholds live in `config.yaml` — nothing is hardcoded.

## How iptables Blocking Works

The blocking mechanism directly interfaces with the Linux kernel firewall:

* When an IP is flagged, `blocker.py` executes: `subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])`
* `-I INPUT 1` inserts the rule at position 1. This is the highest priority, ensuring the block is evaluated before any other Docker or system rule.
* The entire ban operation, including the Slack alert notification, is strictly bound to complete within 10 seconds.
* Bans follow an escalating backoff schedule: `10 min → 30 min → 2 hours → permanent`.
* Unbanning is handled by a background thread executing: `subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])`
* After the fourth ban, the IP is marked as permanent and never automatically released.

## Repository Structure

```text
detector/
  main.py
  monitor.py
  baseline.py
  detector.py
  blocker.py
  unbanner.py
  notifier.py
  dashboard.py
  config.yaml
  requirements.txt
nginx/
  nginx.conf
docs/
  architecture.png
screenshots/
README.md
```

## Setup Instructions

Follow these steps to deploy the full stack on a fresh Ubuntu 24.04 VPS:

1. **System update and package installation:**
   ```bash
   sudo apt-get update && sudo apt-get upgrade -y
   sudo apt-get install -y git docker.io docker-compose-v2 python3-venv iptables
   ```

2. **Clone the repository:**
   ```bash
   git clone https://github.com/MichaelAyz/anomaly-detection-system.git ~/hng-detector
   cd ~/hng-detector
   ```

3. **Configure Notifications:**
   Add your Slack webhook URL to `detector/config.yaml`.

4. **Prepare Audit Logging Directory:**
   ```bash
   sudo mkdir -p /var/log/hng-detector
   sudo chown $USER:$USER /var/log/hng-detector
   ```

5. **Start the Docker stack:**
   ```bash
   docker compose up -d
   ```

6. **Fix Docker volume permissions:**
   Allow the host daemon to read the Nginx JSON logs without requiring root.
   ```bash
   sudo chmod o+x /var/lib/docker
   sudo chmod o+x /var/lib/docker/volumes
   sudo chmod o+x /var/lib/docker/volumes/HNG-nginx-logs
   sudo chmod o+x /var/lib/docker/volumes/HNG-nginx-logs/_data
   sudo chmod o+r /var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log
   ```

7. **Create Python venv and install requirements:**
   ```bash
   cd ~/hng-detector/detector
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

8. **Install and start the systemd service:**
   Create the service file `/etc/systemd/system/hng-detector.service` with the following content:

   ```ini
   [Unit]
   Description=HNG Anomaly Detection Daemon
   After=network.target docker.service
   Requires=docker.service

   [Service]
   Type=simple
   User=ubuntu
   WorkingDirectory=/home/ubuntu/hng-detector/detector
   Environment="PATH=/home/ubuntu/hng-detector/detector/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
   
   # Fix log permissions in case Docker recreated the log file
   ExecStartPre=+/usr/bin/chmod o+r /var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log
   
   ExecStart=/home/ubuntu/hng-detector/detector/venv/bin/python main.py
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

   Then reload and enable the daemon:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable hng-detector
   sudo systemctl start hng-detector
   ```

9. **Verify the Deployment:**
   ```bash
   sudo systemctl status hng-detector
   curl http://localhost:8080/api/metrics
   ```

## Blog Post

https://medium.com/@michaelayozie15/my-server-was-under-attack-f36b888d2fa3

## GitHub Repository

[https://github.com/MichaelAyz/anomaly-detection-system.git](https://github.com/MichaelAyz/anomaly-detection-system.git)
