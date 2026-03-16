import os
import json
import time
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from models import init_db, SessionLocal, AccessLog
from crowdsec import CrowdSecManager
from user_agents import parse
import logging
import maxminddb
from datetime import datetime, timedelta
from sqlalchemy import func
import re
import requests

LOG_FILE = "/app/logs/access.log"
CITY_DB = "/app/geoip/city.mmdb"
ASN_DB = "/app/geoip/asn.mmdb"
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ATTACK_PATTERNS = [
    r"\.\./", r"etc/passwd", r"wp-login", r"sql", r"phpinfo", r"eval\(", 
    r"base64_", r"\.env", r"cmd\.exe", r"/proc/self/", r"<script>", r"SELECT%20",
    r"union\s+select", r"sys_exec", r"shell_exec", r"wget\s", r"curl\s", r"python\s",
    r"perl\s", r"bash\s", r"sh\s", r"cgi-bin", r"admin/config", r"wp-config",
    r"\.git", r"\.svn", r"\.htaccess", r"id_rsa", r"id_dsa", r"shadow", r"htpasswd"
]

class GeoResolver:
    def __init__(self):
        self.city_reader = None
        self.asn_reader = None
        try:
            if os.path.exists(CITY_DB): self.city_reader = maxminddb.open_database(CITY_DB)
            if os.path.exists(ASN_DB): self.asn_reader = maxminddb.open_database(ASN_DB)
        except Exception as e: logger.error(f"GeoIP Error: {e}")

    def resolve(self, ip):
        res = {"country_code": None, "country_name": None, "city": None, "asn": None}
        if not ip: return res
        try:
            if self.city_reader:
                match = self.city_reader.get(ip)
                if match:
                    res["country_code"] = match.get('country', {}).get('iso_code')
                    res["country_name"] = match.get('country', {}).get('names', {}).get('en')
                    res["city"] = match.get('city', {}).get('names', {}).get('en')
            if self.asn_reader:
                match = self.asn_reader.get(ip)
                if match: res["asn"] = f"AS{match.get('autonomous_system_number')}"
        except: pass
        return res

class LogHandler(FileSystemEventHandler):
    def __init__(self, geo, crowdsec=None):
        self.geo = geo
        self.crowdsec = crowdsec
        self.last_pos = 0
        self.blocked_ips_cache = set() 
        self.rate_limit_cache = {} # IP -> [timestamps]
        self.last_cleanup = time.time()

    def notify_discord(self, ip, reason, path, country_code):
        if not DISCORD_WEBHOOK: return
        try:
            payload = {
                "embeds": [{
                    "title": "🚨 God Mode Protection",
                    "description": f"IP `{ip}` has been blocked for malicious activity.",
                    "color": 0xFF0000,
                    "fields": [
                        {"name": "Reason", "value": reason, "inline": True},
                        {"name": "Path", "value": f"`{path}`", "inline": True},
                        {"name": "Country", "value": country_code if country_code else "Unknown", "inline": True}
                    ],
                    "timestamp": datetime.now().isoformat()
                }]
            }
            requests.post(DISCORD_WEBHOOK, json=payload, timeout=5)
        except Exception as e: logger.error(f"Discord error: {e}")

    def check_rate_limit(self, ip):
        now = time.time()
        # Periodically clean cache
        if now - self.last_cleanup > 60:
            self.rate_limit_cache = {k: [t for t in v if now - t < 60] for k, v in self.rate_limit_cache.items()}
            self.rate_limit_cache = {k: v for k, v in self.rate_limit_cache.items() if v}
            self.last_cleanup = now

        if ip not in self.rate_limit_cache: self.rate_limit_cache[ip] = []
        self.rate_limit_cache[ip].append(now)
        # 60 requests in 60 seconds
        return len([t for t in self.rate_limit_cache[ip] if now - t < 60]) > 60

    def on_modified(self, event):
        if event.src_path == LOG_FILE: 
            self.process_new_lines()

    def clean_ip(self, addr):
        if not addr: return ""
        if ':' in addr:
            return addr.split(']')[0].replace('[', '') if addr.startswith('[') else addr.rsplit(':', 1)[0]
        return addr

    def is_attack(self, path):
        if not path: return False
        for p in ATTACK_PATTERNS:
            if re.search(p, path, re.IGNORECASE): return True
        return False

    def process_new_lines(self):
        session = SessionLocal()
        new_count = 0
        try:
            latest_db_entry = session.query(func.max(AccessLog.start_local)).scalar()
            
            if not os.path.exists(LOG_FILE):
                return

            with open(LOG_FILE, 'r') as f:
                f.seek(self.last_pos)
                for line in f:
                    try:
                        data = json.loads(line)
                        log_time = pd.to_datetime(data.get('StartLocal'))
                        
                        if latest_db_entry and log_time.replace(tzinfo=None) <= latest_db_entry.replace(tzinfo=None):
                            continue
                        
                        ip = self.clean_ip(data.get('ClientAddr', ''))
                        geo_info = self.geo.resolve(ip)
                        ua = parse(data.get('RequestUserAgent', ''))
                        path = data.get('RequestPath', '')
                        
                        attack = self.is_attack(path)
                        reason = f"Attack pattern: {path}" if attack else None
                        
                        # Mark as attack if rate limited
                        if not attack: 
                            if self.check_rate_limit(ip):
                                attack = True
                                reason = "Rate limited / Bruteforce"
                        
                        if attack and self.crowdsec and ip not in self.blocked_ips_cache:
                            # Automatic block in CrowdSec
                            self.crowdsec.block_ip(ip, reason=reason)
                            self.notify_discord(ip, reason, path, geo_info["country_code"])
                            self.blocked_ips_cache.add(ip)
                        
                        session.add(AccessLog(
                            start_local=log_time,
                            client_addr=ip,
                            country_code=geo_info["country_code"],
                            country_name=geo_info["country_name"],
                            city_name=geo_info["city"],
                            asn=geo_info["asn"],
                            request_method=data.get('RequestMethod'),
                            request_path=path,
                            request_host=data.get('RequestHost'),
                            request_protocol=data.get('RequestProtocol'),
                            request_referer=data.get('RequestReferer'),
                            request_user_agent=data.get('RequestUserAgent'),
                            is_bot=ua.is_bot,
                            is_attack=attack,
                            browser_family=ua.browser.family,
                            os_family=ua.os.family,
                            device_family=ua.device.family,
                            entry_point=data.get('EntryPointName'),
                            status_code=int(data.get('DownstreamStatus', 0)),
                            duration=int(data.get('Duration', 0)),
                            content_size=int(data.get('DownstreamContentSize', 0))
                        ))
                        new_count += 1
                        if new_count % 100 == 0:
                            session.commit()
                    except Exception as e:
                        session.rollback()
                        continue
                session.commit()
                self.last_pos = f.tell()
                if new_count > 0:
                    logger.info(f"Processed {new_count} new log lines.")
        finally:
            session.close()

def prune_logs():
    days = int(os.getenv("RETENTION_DAYS", "30"))
    if days <= 0: return
    cutoff = datetime.now() - timedelta(days=days)
    session = SessionLocal()
    try:
        deleted = session.query(AccessLog).filter(AccessLog.start_local < cutoff).delete()
        session.commit()
    except Exception as e: logger.error(f"Prune Error: {e}")
    finally: session.close()

if __name__ == "__main__":
    init_db()
    geo = GeoResolver()
    crowdsec = CrowdSecManager()
    logger.info("Ultra Worker started (Enhanced Sync + CrowdSec + Discord).")
    
    handler = LogHandler(geo, crowdsec)
    # Perform initial sync
    handler.process_new_lines()
    
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE), recursive=False)
    observer.start()
    
    last_prune = time.time()
    try:
        while True:
            time.sleep(30)
            handler.process_new_lines()
            
            if time.time() - last_prune > 3600:
                prune_logs()
                last_prune = time.time()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
