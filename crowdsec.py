import logging
import requests
import os
from typing import Optional, List

logger = logging.getLogger(__name__)

class CrowdSecManager:
    def __init__(self):
        self.api_url = os.getenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080").rstrip("/")
        self.api_key = os.getenv("CROWDSEC_LAPI_KEY")
        self.machine_login = os.getenv("CROWDSEC_MACHINE_LOGIN", "localhost")
        self.machine_password = os.getenv("CROWDSEC_MACHINE_PASSWORD")
        
        # Headers for bouncer operations (GET/DELETE)
        self.bouncer_headers = {
            "X-Api-Key": self.api_key,
            "User-Agent": "traefik-god-mode",
        }
        
        # Headers for machine operations (POST) - using password auth
        self.machine_headers = {
            "User-Agent": "traefik-god-mode",
        }

    def _get_token(self) -> Optional[str]:
        """Holt ein JWT-Token von der CrowdSec LAPI."""
        url = f"{self.api_url}/v1/watchers/login"
        payload = {
            "machine_id": self.machine_login,
            "password": self.machine_password
        }
        try:
            resp = requests.post(url, json=payload, timeout=5)
            if resp.status_code == 200:
                return resp.json().get("token")
            logger.error(f"Token fetch failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.error(f"Failed to get CrowdSec token: {e}")
        return None

    def block_ip(self, ip: str, duration: str = "24h", reason: str = "Traefik God Mode Detection"):
        """Create a ban decision in CrowdSec via LAPI."""
        token = self._get_token()
        if not token:
            return False
            
        url = f"{self.api_url}/v1/alerts"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        
        alerts = [{
            "scenario": reason,
            "message": reason,
            "source": {
                "scope": "Ip",
                "value": ip
            },
            "events_count": 1,
            "start_at": now,
            "stop_at": now,
            "decisions": [
                {
                    "duration": duration,
                    "origin": "traefik-god-mode",
                    "scenario": reason,
                    "scope": "Ip",
                    "type": "ban",
                    "value": ip
                }
            ]
        }]
        
        try:
            resp = requests.post(url, headers=headers, json=alerts, timeout=5)
            success = resp.status_code in (200, 201)
            if not success:
                logger.error(f"CrowdSec block failed: {resp.status_code} - {resp.text}")
            return success
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False

    def unblock_ip(self, ip: str):
        """Remove all active decisions for a specific IP via LAPI."""
        token = self._get_token()
        if not token:
            return False
            
        url = f"{self.api_url}/v1/decisions"
        params = {"ip": ip}
        headers = {
            "Authorization": f"Bearer {token}"
        }
        
        try:
            resp = requests.delete(url, headers=headers, params=params, timeout=5)
            success = resp.status_code in (200, 204)
            if not success:
                logger.error(f"CrowdSec unblock failed: {resp.status_code} - {resp.text}")
            return success
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            return False

    def get_ip_reputation(self, ip: str) -> Optional[dict]:
        """Check if an IP has active decisions."""
        if not self.api_key:
            return None

        url = f"{self.api_url}/v1/decisions"
        params = {"ip": ip}

        try:
            response = requests.get(url, headers=self.bouncer_headers, params=params, timeout=5)
            if response.status_code == 200:
                decisions = response.json()
                return decisions[0] if decisions else None
        except:
            pass
        return None

    def get_all_decisions(self) -> List[dict]:
        """List all current decisions (bans)."""
        if not self.api_key:
            return []

        url = f"{self.api_url}/v1/decisions"
        try:
            response = requests.get(url, headers=self.bouncer_headers, timeout=5)
            if response.status_code == 200:
                return response.json() or []
        except:
            pass
        return []
