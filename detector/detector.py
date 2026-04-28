"""
detector.py

This module implements the AnomalyDetector class, which analyzes request rates
for individual IPs and globally against the baseline to detect anomalies.
It uses dynamic thresholds, sliding windows via collections.deque, and handles
error surge detection to tighten rules.
"""

import logging
from collections import defaultdict, deque
import yaml
from typing import Dict, Any

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, baseline_tracker, config_path: str = "/home/ubuntu/hng-detector/detector/config.yaml"):
        # Load configuration dynamically
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.tracker = baseline_tracker
        self.window_seconds = self.config.get('sliding_window_seconds', 60)
        
        self.default_zscore_th = self.config.get('zscore_threshold', 3.0)
        self.default_mult_th = self.config.get('rate_multiplier_threshold', 5.0)
        
        self.error_surge_mult = self.config.get('error_surge_multiplier', 3.0)
        self.surge_zscore_th = self.config.get('error_surge_zscore_threshold', 2.0)
        self.surge_rate_mult = self.config.get('error_surge_rate_multiplier', 3.0)
        
        # pure deques for tracking sliding windows
        self.global_window = deque()
        self.ip_windows = defaultdict(deque)
        self.ip_error_windows = defaultdict(deque)

    def process_request(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a new request log line. Evicts stale elements, computes current rates,
        checks for error surges to tighten thresholds, and finally tests for
        anomalies via z-score and multiplication bounds.
        """
        ip = log_entry.get("source_ip", "-")
        
        ts_str = log_entry.get("timestamp")
        if ts_str:
            from datetime import datetime
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                now = dt.timestamp()
            except ValueError:
                import time
                now = time.time()
        else:
            import time
            now = time.time()
            
        status = int(log_entry.get("status", 200))
        is_error = status >= 400
        
        # Push to deques
        self.global_window.append(now)
        self.ip_windows[ip].append(now)
        if is_error:
            self.ip_error_windows[ip].append(now)
            
        # Evict timestamps older than exactly window_seconds
        cutoff = now - self.window_seconds
        
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()
            
        while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
            self.ip_windows[ip].popleft()
            
        while self.ip_error_windows[ip] and self.ip_error_windows[ip][0] < cutoff:
            self.ip_error_windows[ip].popleft()
            
        # Determine exact rolling RPS per ip and globally
        ip_rps = len(self.ip_windows[ip]) / self.window_seconds
        global_rps = len(self.global_window) / self.window_seconds
        
        # Load baseline dynamically
        mean, stddev, error_mean, error_stddev = self.tracker.get_baseline()
        
        effective_zscore_th = self.default_zscore_th
        effective_mult_th = self.default_mult_th
        tightened = False
        
        # Error surge logic: if anomalous error rates, become stricter
        ip_error_rps = len(self.ip_error_windows[ip]) / self.window_seconds
        if error_mean > 0 and ip_error_rps > (self.error_surge_mult * error_mean):
            effective_zscore_th = self.surge_zscore_th
            effective_mult_th = self.surge_rate_mult
            tightened = True
            
        result = {
            "type": None,
            "ip": ip,
            "ip_rps": ip_rps,
            "global_rps": global_rps,
            "zscore": 0.0,
            "condition": None,
            "tightened": tightened
        }
        
        # IP detection check
        ip_zscore = (ip_rps - mean) / stddev if stddev > 0 else 0.0
        result["zscore"] = ip_zscore
        
        if ip_zscore > effective_zscore_th:
            result["type"] = "ip"
            result["condition"] = f"zscore > {effective_zscore_th}"
            return result
        elif ip_rps > (effective_mult_th * mean):
            result["type"] = "ip"
            result["condition"] = f"rate > {effective_mult_th}x baseline"
            return result
            
        # Global detection check
        global_zscore = (global_rps - mean) / stddev if stddev > 0 else 0.0
        
        if global_zscore > self.default_zscore_th:
            result["type"] = "global"
            result["zscore"] = global_zscore
            result["condition"] = f"global zscore > {self.default_zscore_th}"
            return result
        elif global_rps > (self.default_mult_th * mean):
            result["type"] = "global"
            result["zscore"] = global_zscore
            result["condition"] = f"global rate > {self.default_mult_th}x baseline"
            return result
            
        return result
