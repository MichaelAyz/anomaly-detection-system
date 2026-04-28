"""
baseline.py

This module implements the BaselineTracker class, which maintains a rolling window
of per-second request and error counts. It calculates the mean and standard deviation
for standard and error requests, either using the current hour's aggregated slots or
a fallback 30-minute rolling window.
"""

import math
import statistics
import logging
from collections import deque
from datetime import datetime
import time
import yaml
from typing import Tuple, Dict, List

logger = logging.getLogger(__name__)

class BaselineTracker:
    def __init__(self, config_path: str = "/home/ubuntu/hng-detector/detector/config.yaml"):
        # Load configuration using PyYAML
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.baseline_window_minutes = self.config.get('baseline_window_minutes', 30)
        self.baseline_window_seconds = self.baseline_window_minutes * 60
        self.min_samples = self.config.get('min_baseline_samples', 10)
        self.floor_rps = self.config.get('baseline_floor_rps', 0.1)
        self.audit_log_path = self.config.get('audit_log_path', '/var/log/hng-detector/audit.log')
        
        # Deques of (timestamp, count)
        self.rolling_window = deque()
        self.error_rolling_window = deque()
        
        # Dict of per-hour slots: {hour_int: [rps_values]}
        self.hour_slots: Dict[int, List[float]] = {}
        
        # Current bucket state
        self.current_sec = 0
        self.current_count = 0
        self.current_error_count = 0
        
        # Cached baseline metrics
        self.mean = self.floor_rps
        self.stddev = 0.0
        self.error_mean = 0.0
        self.error_stddev = 0.0

    def _flush_bucket(self, until_sec: int):
        """Flushes the current bucket into the deques, filling gaps with zeros."""
        if self.current_sec == 0:
            return
            
        # Push the current bucket
        self.rolling_window.append((self.current_sec, self.current_count))
        self.error_rolling_window.append((self.current_sec, self.current_error_count))
        
        # Add to hour slot
        hour_int = datetime.fromtimestamp(self.current_sec).hour
        if hour_int not in self.hour_slots:
            self.hour_slots[hour_int] = []
        self.hour_slots[hour_int].append(float(self.current_count))
        
        # Fill zero buckets for seconds between current_sec and until_sec
        gap = min(until_sec - self.current_sec - 1, self.baseline_window_seconds)
        if gap > 0:
            for i in range(1, gap + 1):
                fill_sec = self.current_sec + i
                self.rolling_window.append((fill_sec, 0))
                self.error_rolling_window.append((fill_sec, 0))
                
                f_hour = datetime.fromtimestamp(fill_sec).hour
                if f_hour not in self.hour_slots:
                    self.hour_slots[f_hour] = []
                self.hour_slots[f_hour].append(0.0)

    def record_request(self, timestamp: float, is_error: bool):
        """
        Records a single request into the appropriate per-second bucket.
        """
        req_sec = math.floor(timestamp)
        
        if self.current_sec == 0:
            self.current_sec = req_sec
            
        if req_sec > self.current_sec:
            # Advance to the new second bucket
            self._flush_bucket(req_sec)
            self.current_sec = req_sec
            self.current_count = 1
            self.current_error_count = 1 if is_error else 0
        elif req_sec == self.current_sec:
            # Accumulate in current bucket
            self.current_count += 1
            if is_error:
                self.current_error_count += 1
        else:
            # Drop past-second arrivals to preserve exact strictly-increasing time window
            pass

    def get_global_rps(self, now: float) -> float:
        """
        Returns the average RPS over the last 60 seconds from the baseline tracking.
        """
        cutoff = now - 60
        total_requests = 0
        for i in range(len(self.rolling_window)-1, -1, -1):
            ts, count = self.rolling_window[i]
            if ts >= cutoff:
                total_requests += count
            else:
                break
        return total_requests / 60.0

    def recalculate(self):
        """
        Evicts stale entries, computes statistics, and logs an audit entry.
        Called periodically (e.g., every 60 seconds).
        """
        now = time.time()
        cutoff = now - self.baseline_window_seconds
        
        # Evict old entries from rolling windows
        while self.rolling_window and self.rolling_window[0][0] < cutoff:
            self.rolling_window.popleft()
            
        while self.error_rolling_window and self.error_rolling_window[0][0] < cutoff:
            self.error_rolling_window.popleft()
            
        current_hour = datetime.fromtimestamp(now).hour
        
        # Clean up old hour slots to conserve memory
        stale_hours = [h for h in self.hour_slots.keys() if h != current_hour and h != (current_hour - 1) % 24]
        for h in stale_hours:
            del self.hour_slots[h]
            
        source = "rolling"
        sample_counts = [count for _, count in self.rolling_window]
        
        # Prefer hour slot data if sufficient samples exist
        if current_hour in self.hour_slots and len(self.hour_slots[current_hour]) >= self.min_samples:
            source = "hour-slot"
            sample_counts = self.hour_slots[current_hour]
            
        sample_count = len(sample_counts)
        
        if sample_count > 1:
            computed_mean = statistics.mean(sample_counts)
            self.stddev = statistics.stdev(sample_counts)
        elif sample_count == 1:
            computed_mean = sample_counts[0]
            self.stddev = 0.0
        else:
            computed_mean = 0.0
            self.stddev = 0.0
            
        # Ensure a non-zero floor for baseline
        self.mean = max(computed_mean, self.floor_rps)
        
        # Error statistics
        error_counts = [count for _, count in self.error_rolling_window]
        if len(error_counts) > 1:
            self.error_mean = statistics.mean(error_counts)
            self.error_stddev = statistics.stdev(error_counts)
        elif len(error_counts) == 1:
            self.error_mean = error_counts[0]
            self.error_stddev = 0.0
        else:
            self.error_mean = 0.0
            self.error_stddev = 0.0
            
        # Write to audit log: Format: [timestamp] ACTION ip | condition | rate | baseline | duration
        timestamp_str = datetime.utcnow().isoformat() + "Z"
        audit_msg = (
            f"[{timestamp_str}] BASELINE_RECALC | "
            f"effective_mean={self.mean:.2f}rps | "
            f"effective_stddev={self.stddev:.2f} | "
            f"samples={sample_count} | source={source}"
        )
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(audit_msg + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def get_baseline(self) -> Tuple[float, float, float, float]:
        """Returns computed metrics: (mean, stddev, error_mean, error_stddev)"""
        return self.mean, self.stddev, self.error_mean, self.error_stddev
