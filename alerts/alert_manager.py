#later add tlrgaram bot
#fix data base error
#bot written by ai fix it

import json
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional

import requests

from database.database import db
from utils.config import (
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    ALERT_MIN_SEVERITY,
    TERMINAL_COLORS,
    severity_gte,
)

logger = logging.getLogger(__name__)


# colorcodes

_RESET  = "\033[0m"
_COLORS: Dict[str, str] = {
    "INFO":     "\033[96m",   
    "LOW":      "\033[92m",   
    "MEDIUM":   "\033[93m",   
    "HIGH":     "\033[91m",   
    "CRITICAL": "\033[1;91m", 
}

# Telegram API endpoint template
_TG_URL = "https://api.telegram.org/bot{token}/sendMessage"


class AlertManager:
    

    def __init__(
        self,
        telegram_token:   str = TELEGRAM_BOT_TOKEN,
        telegram_chat_id: str = TELEGRAM_CHAT_ID,
        min_severity:     str = ALERT_MIN_SEVERITY,
    ):
        self._tg_token    = telegram_token
        self._tg_chat_id  = telegram_chat_id
        self._min_severity = min_severity

    
    # PUBLIC API
    

    def send(self, alert: Dict[str, Any]) -> None:
    
        # to salt with timestamp if missing
        alert.setdefault("timestamp", datetime.utcnow().isoformat(timespec="seconds"))

        self._terminal_alert(alert)
        event_id = self._persist(alert)

        if severity_gte(alert.get("severity", "LOW"), self._min_severity):
            self._telegram_alert(alert, event_id)

    
    # Channels

    def _terminal_alert(self, alert: Dict[str, Any]) -> None:
        severity = alert.get("severity", "MEDIUM")
        color    = _COLORS.get(severity, "") if TERMINAL_COLORS else ""
        reset    = _RESET if TERMINAL_COLORS else ""
        ts       = alert.get("timestamp", "")

        line = (
            f"{color}"
            f"[{ts}] [{severity}] {alert.get('attack_type','UNKNOWN')} | "
            f"src={alert.get('source_ip','?')} → dst={alert.get('dest_ip','?')} | "
            f"{alert.get('message','')}"
            f"{reset}"
        )
        print(line)
        logger.warning(
            "[%s] %s src=%s dst=%s",
            severity,
            alert.get("attack_type"),
            alert.get("source_ip"),
            alert.get("dest_ip"),
        )

    def _persist(self, alert: Dict[str, Any]) -> Optional[int]:
        """Write event to SQLite.  Returns the new row id."""
        try:
            # Collect any extra fields into packet_info JSON blob
            known_keys = {
                "attack_type", "source_ip", "dest_ip",
                "src_port", "dest_port", "protocol",
                "severity", "message", "timestamp",
            }
            extra = {k: v for k, v in alert.items() if k not in known_keys}

            event_id = db.insert_event(
                attack_type = alert.get("attack_type", "UNKNOWN"),
                source_ip   = alert.get("source_ip", ""),
                dest_ip     = alert.get("dest_ip", ""),
                source_port = int(alert.get("src_port", 0)),
                dest_port   = int(alert.get("dest_port", 0)),
                protocol    = alert.get("protocol", ""),
                packet_info = json.dumps(extra, default=str),
                severity    = alert.get("severity", "MEDIUM"),
            )
            return event_id
        except Exception as exc:
            logger.error("Failed to persist alert: %s", exc)
            return None

    def _telegram_alert(self, alert: Dict[str, Any], event_id: Optional[int]) -> None:
        """Send a Telegram message for high-severity alerts."""
        if not self._tg_token or not self._tg_chat_id:
            logger.debug("Telegram not configured – skipping notification.")
            return

        severity = alert.get("severity", "MEDIUM")
        emoji_map = {
            "INFO":     "ℹ️",
            "LOW":      "🟢",
            "MEDIUM":   "🟡",
            "HIGH":     "🔴",
            "CRITICAL": "🚨",
        }
        emoji = emoji_map.get(severity, "⚠️")

        text = (
            f"{emoji} *NIDS Alert #{event_id}*\n"
            f"*Type:* `{alert.get('attack_type')}`\n"
            f"*Severity:* `{severity}`\n"
            f"*Source IP:* `{alert.get('source_ip')}`\n"
            f"*Dest IP:* `{alert.get('dest_ip')}`\n"
            f"*Time:* `{alert.get('timestamp')}`\n"
            f"*Details:* {alert.get('message', '')}"
        )

        url  = _TG_URL.format(token=self._tg_token)
        data = {
            "chat_id":    self._tg_chat_id,
            "text":       text,
            "parse_mode": "Markdown",
        }

        try:
            resp = requests.post(url, json=data, timeout=5)
            resp.raise_for_status()
            logger.debug("Telegram alert sent (event #%s).", event_id)
            if event_id:
                db.mark_alerted(event_id)
        except requests.RequestException as exc:
            logger.warning("Telegram notification failed: %s", exc)
