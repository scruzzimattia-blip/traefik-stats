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
import ipaddress
import concurrent.futures
from typing import Any
from pydantic import BaseModel, ConfigDict

LOG_FILE = "/app/logs/access.log"
CITY_DB = "/app/geoip/city.mmdb"
ASN_DB = "/app/geoip/asn.mmdb"
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Executor for async background tasks
executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

def try_int(val: Any) -> int:
    try:
        if val is None or val == '': return 0
        return int(val)
    except:
        return 0

class TraefikLogData(BaseModel):
    model_config = ConfigDict(extra='ignore')
    StartLocal: str = ""
    ClientAddr: str = ""
    RequestUserAgent: str = ""
    RequestPath: str = ""
    RequestHost: str = ""
    RequestMethod: str = ""
    RequestProtocol: str = ""
    RequestReferer: str = ""
    EntryPointName: str = ""
    DownstreamStatus: Any = 0
    Duration: Any = 0
    DownstreamContentSize: Any = 0

ATTACK_PATTERNS = [
    r"\.\./", r"etc/passwd", r"wp-login", r"sql", r"phpinfo", r"eval\(", 
    r"base64_", r"\.env", r"cmd\.exe", r"/proc/self/", r"<script>", r"SELECT%20",
    r"union\s+select", r"sys_exec", r"shell_exec", r"wget\s", r"curl\s", r"python\s",
    r"perl\s", r"bash\s", r"sh\s", r"cgi-bin", r"admin/config", r"wp-config",
    r"\.git", r"\.svn", r"\.htaccess", r"id_rsa", r"id_dsa", r"shadow", r"htpasswd"
]
ATTACK_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in ATTACK_PATTERNS]

IGNORED_IPS_SET = set(os.getenv("IGNORED_IPS", "92.106.189.142").split(","))

# Precompute networks for CIDR support
IGNORED_NETWORKS = []
for ip_str in IGNORED_IPS_SET:
    try:
        IGNORED_NETWORKS.append(ipaddress.ip_network(ip_str.strip(), strict=False))
    except ValueError:
        pass

def should_ignore_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        for net in IGNORED_NETWORKS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False

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
        self.whitelist_hosts = {"cloud.scruzzi.com", "jellyfin.scruzzi.com"}
        self.error_tracker = {} # ip -> [list of timestamps]

    def check_rate_limit(self, ip, timestamp, host):
        if host in self.whitelist_hosts:
            return False
            
        now = timestamp.timestamp()
        if ip not in self.error_tracker:
            self.error_tracker[ip] = []
            
        # keep only last 60 seconds
        self.error_tracker[ip] = [t for t in self.error_tracker[ip] if now - t < 60]
        self.error_tracker[ip].append(now)
        
        # Soft-Ban if > 20 errors in 60 seconds
        return len(self.error_tracker[ip]) > 20

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
        for p in ATTACK_PATTERNS_COMPILED:
            if p.search(path): return True
        return False

    def process_new_lines(self):
        session = SessionLocal()
        new_count = 0
        try:
            latest_db_entry = session.query(func.max(AccessLog.start_local)).scalar()
            
            if not os.path.exists(LOG_FILE):
                return
                
            if os.path.getsize(LOG_FILE) < self.last_pos:
                # Log rotation detected
                self.last_pos = 0

            with open(LOG_FILE, 'r') as f:
                f.seek(self.last_pos)
                for line in f:
                    try:
                        raw_data = json.loads(line)
                        log_data = TraefikLogData(**raw_data)
                        
                        raw_time = log_data.StartLocal
                        if not raw_time:
                            continue
                            
                        if raw_time.endswith('Z'):
                            raw_time = raw_time[:-1] + '+00:00'
                        
                        try:
                            log_time = datetime.fromisoformat(raw_time)
                        except ValueError:
                            log_time = pd.to_datetime(raw_time)
                            
                        if latest_db_entry and log_time.replace(tzinfo=None) <= latest_db_entry.replace(tzinfo=None):
                            continue
                        
                        ip = self.clean_ip(log_data.ClientAddr)
                        
                        # Skip monitoring for ignored IPs
                        if should_ignore_ip(ip):
                            continue

                        geo_info = self.geo.resolve(ip)
                        ua = parse(log_data.RequestUserAgent)
                        path = log_data.RequestPath
                        host = log_data.RequestHost
                        
                        attack = self.is_attack(path)
                        reason = f"Attack pattern: {path}" if attack else None
                        
                        status_code = try_int(log_data.DownstreamStatus)
                        
                        # Soft-Ban Check
                        if not attack and status_code >= 400:
                            if self.check_rate_limit(ip, log_time, host):
                                attack = True
                                reason = "Rate Limit Exceeded (High Error Rate)"
                        
                        if attack and self.crowdsec and ip not in self.blocked_ips_cache:
                            # Automatic block in CrowdSec (Async)
                            executor.submit(self.crowdsec.block_ip, ip, "24h", reason)
                            executor.submit(self.notify_discord, ip, reason, path, geo_info["country_code"])
                            self.blocked_ips_cache.add(ip)
                        
                        log_entry = AccessLog(
                            start_local=log_time,
                            client_addr=ip,
                            country_code=geo_info["country_code"],
                            country_name=geo_info["country_name"],
                            city_name=geo_info["city"],
                            asn=geo_info["asn"],
                            request_method=log_data.RequestMethod,
                            request_path=path,
                            request_host=host,
                            request_protocol=log_data.RequestProtocol,
                            request_referer=log_data.RequestReferer,
                            request_user_agent=log_data.RequestUserAgent,
                            is_bot=ua.is_bot,
                            is_attack=attack,
                            browser_family=ua.browser.family,
                            os_family=ua.os.family,
                            device_family=ua.device.family,
                            entry_point=log_data.EntryPointName,
                            status_code=status_code,
                            duration=try_int(log_data.Duration),
                            content_size=try_int(log_data.DownstreamContentSize)
                        )
                        session.add(log_entry)
                        new_count += 1
                        
                        if new_count % 100 == 0:
                            try:
                                session.commit()
                            except Exception as e:
                                session.rollback()
                                logger.error(f"Batch commit error: {e}")
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Error parsing log line: {e}")
                        continue
                        
                try:
                    session.commit()
                except Exception as e:
                    session.rollback()
                    logger.error(f"Final batch commit error: {e}")
                    
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

def notify_critical_error(err_msg):
    if not DISCORD_WEBHOOK: return
    try:
        payload = {
            "embeds": [{
                "title": "🔥 God Mode Crash Alert",
                "description": f"Worker encountered a critical error:\n```\n{err_msg}\n```",
                "color": 0xFF0000,
                "timestamp": datetime.now().isoformat()
            }]
        }
        executor.submit(requests.post, DISCORD_WEBHOOK, json=payload, timeout=5)
    except Exception: pass

if __name__ == "__main__":
    try:
        init_db()
    except Exception as e:
        logger.error(f"DB Init Error: {e}")
        notify_critical_error(f"DB Init Error: {e}")
        exit(1)
        
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
    except Exception as e:
        logger.error(f"Critical Worker Loop Error: {e}")
        notify_critical_error(f"Worker Loop Error: {e}")
        observer.stop()
    observer.join()
