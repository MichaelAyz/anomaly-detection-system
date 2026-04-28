"""
main.py

The central entrypoint for the HNG Anomaly Detection Daemon.
This module wires together the monitor, baseline tracker, detector, blocker, unbanner,
notifier, and dashboard components. It runs an infinite loop reading log entries
and delegates them for processing and enforcement.
"""

import time
import logging
import threading
import sys
import os
import yaml

from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard
import monitor

# Step 1 — Logging setup: Configure Python logging to stdout, level INFO
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(name)s — %(message)s'
)
logger = logging.getLogger("main")

def main():
    try:
        config_path = "/home/ubuntu/hng-detector/detector/config.yaml"
        
        # Read log_path and config_path from config.yaml at startup
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        log_path = config.get('log_path', '/var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log')
        
        # Startup banner logged at INFO level
        logger.info(f"HNG Anomaly Detector starting, config path: {config_path}, log path: {log_path}, dashboard URL: http://yzmetrics.duckdns.org:8080")
        
        # Step 2 — Audit log directory
        os.makedirs("/var/log/hng-detector/", exist_ok=True)
        
        # Step 3 — Instantiation order (exact)
        notifier = Notifier(config_path)
        blocker = Blocker(notifier, config_path)
        baseline_tracker = BaselineTracker(config_path)
        # Using the actual signature from our detector.py implementation
        detector = AnomalyDetector(baseline_tracker, config_path)
        unbanner = Unbanner(blocker, notifier, config_path)
        
        # Step 4 — Start supporting threads
        unbanner.start()  # daemon thread
        start_time = time.time()
        dashboard = Dashboard(blocker, baseline_tracker, detector, start_time, config_path)
        dashboard.start()  # daemon thread
        
        # Step 5 — Baseline recalculation thread
        def recalculate_loop():
            while True:
                time.sleep(60)
                baseline_tracker.recalculate()
                
        recalc_thread = threading.Thread(target=recalculate_loop, daemon=True)
        recalc_thread.start()
        
        # Step 6 — Main loop
        request_count = 0
        for log_entry in monitor.tail_log(log_path):
            now = time.time()
            is_error = log_entry.get("status", 0) >= 400
            
            # Record request in the baseline tracker
            baseline_tracker.record_request(now, is_error)
            
            # Check the request for anomalies
            result = detector.process_request(log_entry)
            
            if result["type"] == "ip":
                ip = result["ip"]
                # Check if the IP is already banned before acting
                if not blocker.is_banned(ip):
                    mean, stddev, _, _ = baseline_tracker.get_baseline()
                    # Trigger an IP ban
                    blocker.ban(
                        ip=ip,
                        reason=result["condition"],
                        rate=result["ip_rps"],
                        baseline=mean,
                        zscore=result["zscore"],
                        tightened=result["tightened"]
                    )
            elif result["type"] == "global":
                mean, _, _, _ = baseline_tracker.get_baseline()
                # Trigger a global alert
                notifier.send_global_alert(
                    condition=result["condition"],
                    global_rps=result["global_rps"],
                    baseline_mean=mean,
                    zscore=result["zscore"]
                )
            
            request_count += 1
            if request_count % 100 == 0:
                mean, stddev, _, _ = baseline_tracker.get_baseline()
                logger.info(
                    f"Heartbeat — processed {request_count} requests | "
                    f"global_rps={result['global_rps']:.3f} | "
                    f"baseline_mean={mean:.3f} | "
                    f"banned={len(blocker.get_banned_ips())}"
                )
                
    except (KeyboardInterrupt, SystemExit):
        # Step 7 — Graceful shutdown
        logger.info("Shutdown signal received — HNG detector stopping cleanly.")
        sys.exit(0)

# Step 8 — Entry point
if __name__ == "__main__":
    main()
