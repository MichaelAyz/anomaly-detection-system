"""
notifier.py

Implements the Notifier class for sending Slack alerts via webhooks.
Uses the Slack Block Kit attachments API to render a colored left sidebar.
"""

import logging
import requests
import yaml
from datetime import datetime

logger = logging.getLogger(__name__)

class Notifier:
    def __init__(self, config_path: str = "/home/ubuntu/hng-detector/detector/config.yaml"):
        # Load slack_webhook_url from config.yaml using PyYAML
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.webhook_url = self.config.get('slack_webhook_url')

    def _send_attachment(self, color: str, blocks: list):
        if not self.webhook_url:
            logger.error("Slack webhook URL not configured.")
            return

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks
                }
            ]
        }
        try:
            # 5-second timeout, wrapped in try/except, errors logged never raised
            resp = requests.post(self.webhook_url, json=payload, timeout=5.0)
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")

    def _get_common_blocks(self):
        """Returns the common actions and context blocks for all alerts."""
        return [
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "View Live Dashboard",
                            "emoji": True
                        },
                        "url": "http://yzmetrics.duckdns.org:8080",
                        "style": "primary"
                    }
                ]
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "HNG Anomaly Detector | cloud.ng | 100.26.113.199"
                    }
                ]
            }
        ]

    def send_ban_alert(self, ip: str, condition: str, rate: float, baseline: float, duration_minutes: int, zscore: float = 0.0, tightened: bool = False) -> None:
        """Sends an alert when an IP is temporarily banned."""
        iso_now = datetime.utcnow().isoformat() + "Z"
        mode_str = "Tightened — Error Surge" if tightened else "Standard"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 IP BANNED",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*An anomalous IP has been blocked.*"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP Address*\n{ip}"},
                    {"type": "mrkdwn", "text": f"*Condition*\n{condition}"},
                    {"type": "mrkdwn", "text": f"*Current Rate*\n{rate:.3f} rps"},
                    {"type": "mrkdwn", "text": f"*Baseline Mean*\n{baseline:.3f} rps"},
                    {"type": "mrkdwn", "text": f"*Z-Score*\n{zscore:.3f}"},
                    {"type": "mrkdwn", "text": f"*Ban Duration*\n{duration_minutes} min"},
                    {"type": "mrkdwn", "text": f"*Threshold Mode*\n{mode_str}"},
                    {"type": "mrkdwn", "text": f"*Timestamp*\n{iso_now}"}
                ]
            }
        ]
        
        blocks.extend(self._get_common_blocks())
        self._send_attachment("#E53935", blocks)

    def send_unban_alert(self, ip: str, ban_count: int, next_duration_minutes) -> None:
        """Sends an alert when an IP is unbanned."""
        iso_now = datetime.utcnow().isoformat() + "Z"
        next_duration = "Permanent" if next_duration_minutes == float('inf') else f"{next_duration_minutes} min"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "✅ IP UNBANNED",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*An IP block has expired and has been removed.*"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP Address*\n{ip}"},
                    {"type": "mrkdwn", "text": f"*Ban Count*\n{ban_count}"},
                    {"type": "mrkdwn", "text": f"*Next Ban Duration*\n{next_duration}"},
                    {"type": "mrkdwn", "text": f"*Released At*\n{iso_now}"}
                ]
            }
        ]
        
        blocks.extend(self._get_common_blocks())
        self._send_attachment("#43A047", blocks)

    def send_permanent_ban_alert(self, ip: str, ban_count: int) -> None:
        """Sends an alert when an IP is permanently banned."""
        iso_now = datetime.utcnow().isoformat() + "Z"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "⛔ PERMANENT BAN APPLIED",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*An IP has exceeded the allowed number of infractions and is now permanently blocked.*"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP Address*\n{ip}"},
                    {"type": "mrkdwn", "text": f"*Total Ban Count*\n{ban_count}"},
                    {"type": "mrkdwn", "text": f"*Status*\nPermanent — Manual removal required"},
                    {"type": "mrkdwn", "text": f"*Timestamp*\n{iso_now}"}
                ]
            }
        ]
        
        blocks.extend(self._get_common_blocks())
        self._send_attachment("#B71C1C", blocks)

    def send_global_alert(self, condition: str, global_rps: float, baseline_mean: float, zscore: float) -> None:
        """Sends an alert for a global traffic anomaly."""
        iso_now = datetime.utcnow().isoformat() + "Z"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🌐 GLOBAL TRAFFIC ANOMALY",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*A significant spike in global traffic has been detected.*"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Condition*\n{condition}"},
                    {"type": "mrkdwn", "text": f"*Global Rate*\n{global_rps:.3f} rps"},
                    {"type": "mrkdwn", "text": f"*Baseline Mean*\n{baseline_mean:.3f} rps"},
                    {"type": "mrkdwn", "text": f"*Z-Score*\n{zscore:.3f}"},
                    {"type": "mrkdwn", "text": f"*Action Taken*\nSlack alert only — no IP block"},
                    {"type": "mrkdwn", "text": f"*Timestamp*\n{iso_now}"}
                ]
            }
        ]
        
        blocks.extend(self._get_common_blocks())
        self._send_attachment("#FB8C00", blocks)
