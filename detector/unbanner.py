"""
unbanner.py

Runs as a background thread to handle automatic expiration of IP bans.
Increments ban counts and escalates ban durations according to a schedule.
"""

import logging
import threading
import time
import subprocess
import yaml
from datetime import datetime

logger = logging.getLogger(__name__)

class Unbanner(threading.Thread):
    def __init__(self, blocker, notifier, config_path: str = "/home/ubuntu/hng-detector/detector/config.yaml"):
        super().__init__(daemon=True)
        self.blocker = blocker
        self.notifier = notifier
        
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.audit_log_path = self.config.get('audit_log_path', '/var/log/hng-detector/audit.log')
        self.schedule = self.config.get('ban_schedule_minutes', [10, 30, 120])
        
    def run(self):
        logger.info("Unbanner thread started.")
        while True:
            time.sleep(30)
            now = time.time()
            
            banned_ips = self.blocker.get_banned_ips()
            for ip, info in list(banned_ips.items()):
                if not info.get('active', False):
                    continue
                    
                duration = info.get('duration_minutes')
                if duration == float('inf'):
                    continue
                    
                banned_at = info.get('banned_at', 0)
                if now - banned_at >= duration * 60:
                    try:
                        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                        logger.info(f"Removed iptables ban for {ip}")
                        
                        info['ban_count'] += 1
                        ban_count = info['ban_count']
                        
                        if ban_count >= len(self.schedule) + 1:
                            # 4th ban means permanent
                            info['duration_minutes'] = float('inf')
                            info['active'] = True
                            info['banned_at'] = now
                            self.notifier.send_permanent_ban_alert(ip, ban_count)
                            
                            timestamp_str = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                            audit_msg = (
                                f"[{timestamp_str}] PERMANENT_BAN ip={ip} | "
                                f"ban_count={ban_count}"
                            )
                            try:
                                with open(self.audit_log_path, 'a') as f:
                                    f.write(audit_msg + "\n")
                            except Exception as e:
                                logger.error(f"Failed to write permanent ban audit log: {e}")
                        else:
                            next_duration = self.schedule[ban_count - 1]
                            info['active'] = False
                            info['duration_minutes'] = next_duration
                            self.notifier.send_unban_alert(ip, ban_count, next_duration)
                            
                            timestamp_str = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                            audit_msg = (
                                f"[{timestamp_str}] UNBAN ip={ip} | "
                                f"ban_count={ban_count} | "
                                f"next_duration={next_duration}min"
                            )
                            try:
                                with open(self.audit_log_path, 'a') as f:
                                    f.write(audit_msg + "\n")
                            except Exception as e:
                                logger.error(f"Failed to write unban audit log: {e}")
                                
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Failed to remove iptables rule for {ip}: {e}")
