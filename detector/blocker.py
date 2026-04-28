"""
blocker.py

This module implements the Blocker class, handling immediate iptables blocks
for anomalous IPs. It tracks banned IPs in memory and delegates alert sending.
It uses subprocess.run to execute actual iptables commands and handles audit logging.
"""

import subprocess
import time
import logging
from datetime import datetime
import yaml
from typing import Dict, Any

logger = logging.getLogger(__name__)

class Blocker:
    def __init__(self, notifier, config_path: str = "/home/ubuntu/hng-detector/detector/config.yaml"):
        # Load configuration dynamically
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.notifier = notifier
        self.audit_log_path = self.config.get('audit_log_path', '/var/log/hng-detector/audit.log')
        self.ban_schedule_minutes = self.config.get('ban_schedule_minutes', [10, 30, 120])
        
        # Tracks current ban state: {ip: {banned_at, ban_count, duration_minutes, active}}
        self.banned_ips: Dict[str, Dict[str, Any]] = {}

    def ban(self, ip: str, reason: str, rate: float, baseline: float,
                zscore: float = 0.0, tightened: bool = False):
        """
        Executes an iptables block on the given IP if not currently banned.
        Determines timeout based on schedule, triggers a Slack alert,
        and safely logs to the local audit file.
        """
        if self.is_banned(ip):
            return
            
        if ip not in self.banned_ips:
            self.banned_ips[ip] = {"banned_at": 0, "ban_count": 0, "duration_minutes": 0, "active": False}
            
        self.banned_ips[ip]["ban_count"] += 1
        ban_count = self.banned_ips[ip]["ban_count"]
        
        # Schedule backoff progression
        idx = ban_count - 1
        if idx < len(self.ban_schedule_minutes):
            duration_minutes = self.ban_schedule_minutes[idx]
        else:
            duration_minutes = float('inf') # Permanent Ban
            
        self.banned_ips[ip]["duration_minutes"] = duration_minutes
        self.banned_ips[ip]["banned_at"] = time.time()
        self.banned_ips[ip]["active"] = True
        
        # Execute direct iptables drop command with exactly a 10 sec timeout limit
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                check=True,
                timeout=10
            )
            logger.info(f"Successfully banned IP: {ip}")
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout banning IP {ip} via iptables.")
            return
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing iptables for {ip}: {e}")
            return
        except Exception as e:
            logger.error(f"Unexpected error banning {ip}: {e}")
            return
            
        # Issue a Slack alert dynamically
        self.notifier.send_ban_alert(ip, reason, rate, baseline,
                              duration_minutes, zscore=zscore,
                              tightened=tightened)
        
        # Construct exact audit string Format: [timestamp] ACTION ip | condition | rate | baseline | duration
        timestamp_str = datetime.utcnow().isoformat() + "Z"
        dur_str = str(duration_minutes) if duration_minutes != float('inf') else "permanent"
        audit_msg = (
            f"[{timestamp_str}] BAN ip={ip} | condition={reason} | "
            f"rate={rate:.2f}rps | baseline={baseline:.2f}rps | duration={dur_str}"
        )
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(audit_msg + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def is_banned(self, ip: str) -> bool:
        """
        Determines whether the given IP is currently active in the ban list.
        """
        info = self.banned_ips.get(ip)
        if not info:
            return False
        return info.get("active", False)

    def get_banned_ips(self) -> Dict[str, Dict[str, Any]]:
        """
        Provides current tracked dictionary of banned IP records.
        """
        return self.banned_ips
