import logging
import requests
import os
from typing import Optional

logger = logging.getLogger(__name__)

class CrowdSecManager:
    def __init__(self):
        self.api_url = os.getenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080").rstrip("/")
        self.api_key = os.getenv("CROWDSEC_LAPI_KEY")
        self.headers = {
            "X-Api-Key": self.api_key,
            "User-Agent": "Traefik-God-Mode",
        }

    def block_ip(self, ip: str, duration: str = "24h", reason: str = "Traefik God Mode Detection"):
        """
        Create a decision in CrowdSec to block an IP.
        Duration format: 24h, 1h, etc.
        """
        if not self.api_key:
            logger.warning("CrowdSec LAPI Key not set. Blocking disabled.")
            return False

        url = f"{self.api_url}/v1/decisions"
        payload = [
            {
                "value": ip,
                "scope": "Ip",
                "type": "ban",
                "origin": "traefik-god-mode",
                "duration": duration,
                "reason": reason
            }
        ]

        try:
            logger.info(f"Blocking IP {ip} in CrowdSec for {duration}. Reason: {reason}")
            response = requests.post(url, headers=self.headers, json=payload, timeout=5)
            if response.status_code == 201:
                return True
            else:
                logger.error(f"CrowdSec LAPI Error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Failed to connect to CrowdSec LAPI: {e}")
            return False

    def get_ip_reputation(self, ip: str) -> Optional[dict]:
        """Check if an IP has any active decisions in CrowdSec."""
        if not self.api_key:
            return None

        url = f"{self.api_url}/v1/decisions"
        params = {"ip": ip}

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=5)
            response.raise_for_status()
            decisions = response.json()

            if decisions and isinstance(decisions, list):
                return decisions[0]
            return None
        except Exception as e:
            logger.error(f"CrowdSec API error for IP {ip}: {e}")
            return None
