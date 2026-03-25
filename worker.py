import os
import json
import time
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from models import init_db, SessionLocal, AccessLog, RateLimitEntry, LoginAttempt, BlockedCountry, WorkerStats
from crowdsec import CrowdSecManager
from user_agents import parse
import logging
import maxminddb
from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.exc import OperationalError
import re
import requests
import ipaddress
import concurrent.futures
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict
import threading
import redis

LOG_FILE = os.getenv("LOG_FILE", "/app/logs/access.log")
CITY_DB = os.getenv("CITY_DB", "/app/geoip/city.mmdb")
ASN_DB = os.getenv("ASN_DB", "/app/geoip/asn.mmdb")
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
REDIS_URL = os.getenv("REDIS_URL", None)

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": datetime.now().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

logger = logging.getLogger(__name__)
if os.getenv("LOG_FORMAT") == "json":
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

logger.info("Starting Traefik God Mode Worker v2.0")

executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

redis_client = None
if REDIS_URL:
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        logger.info("Redis connected for rate limiting")
    except Exception as e:
        logger.warning(f"Redis unavailable, falling back to DB: {e}")

STATS = {"logs_processed": 0, "attacks_detected": 0, "ips_banned": 0, "db_errors": 0, "processing_times": []}
STATS_LOCK = threading.Lock()

def record_stat(key: str, value: Any):
    with STATS_LOCK:
        if key == "processing_time":
            STATS["processing_times"].append(value)
            if len(STATS["processing_times"]) > 100:
                STATS["processing_times"] = STATS["processing_times"][-100:]
        elif key in STATS:
            STATS[key] += value

def get_avg_processing_time() -> float:
    with STATS_LOCK:
        times = STATS["processing_times"]
        return sum(times) / len(times) if times else 0

def flush_stats():
    session = SessionLocal()
    try:
        stats = WorkerStats(
            logs_processed=STATS["logs_processed"],
            attacks_detected=STATS["attacks_detected"],
            ips_banned=STATS["ips_banned"],
            db_errors=STATS["db_errors"],
            avg_processing_time_ms=get_avg_processing_time()
        )
        session.add(stats)
        session.commit()
        with STATS_LOCK:
            STATS["logs_processed"] = 0
            STATS["attacks_detected"] = 0
            STATS["ips_banned"] = 0
            STATS["db_errors"] = 0
    except Exception as e:
        logger.error(f"Failed to flush stats: {e}")
    finally:
        session.close()

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

WHITELIST_HOSTS = set(os.getenv("WHITELIST_HOSTS", "cloud.scruzzi.com,jellyfin.scruzzi.com").split(","))

ATTACK_PATTERNS = [
    r"\.\./", r"etc/passwd", r"wp-login", r"phpinfo", r"eval\(", 
    r"base64_", r"\.env", r"cmd\.exe", r"/proc/self/", r"<script>", r"SELECT%20",
    r"union\s+select", r"sys_exec", r"shell_exec", r"wget\s", r"curl\s", r"python\s",
    r"perl\s", r"bash\s", r"sh\s", r"cgi-bin", r"admin/config", r"wp-config",
    r"/\.git/", r"\.svn", r"\.htaccess", r"id_rsa", r"id_dsa", r"shadow", r"htpasswd",
    r"UNION ALL SELECT", r"INFORMATION_SCHEMA", r"DROP TABLE", r"INSERT INTO"
]

LOGIN_PATTERNS = [
    r"wp-login", r"admin", r"login", r"signin", r"auth", r"dashboard", 
    r"administrator", r"phpadmin", r"phpmyadmin", r"console"
]

ATTACK_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in ATTACK_PATTERNS]
LOGIN_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in LOGIN_PATTERNS]

IGNORED_IPS_SET = set(os.getenv("IGNORED_IPS", "92.106.189.142").split(","))

IGNORED_NETWORKS = []
for ip_str in IGNORED_IPS_SET:
    try:
        IGNORED_NETWORKS.append(ipaddress.ip_network(ip_str.strip(), strict=False))
    except ValueError:
        pass

_blocked_countries_cache: set = set()
_blocked_countries_lock = threading.Lock()

def load_blocked_countries():
    global _blocked_countries_cache
    session = SessionLocal()
    try:
        blocked = session.query(BlockedCountry).filter(BlockedCountry.active == True).all()
        with _blocked_countries_lock:
            _blocked_countries_cache = {b.country_code for b in blocked}
    except Exception as e:
        logger.error(f"Failed to load blocked countries: {e}")
    finally:
        session.close()

def reload_attack_patterns():
    global ATTACK_PATTERNS_COMPILED
    custom_patterns_str = os.getenv("ATTACK_PATTERNS", "")
    if custom_patterns_str:
        patterns = [p.strip() for p in custom_patterns_str.split(",") if p.strip()]
        ATTACK_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in patterns]
        logger.info(f"Reloaded {len(ATTACK_PATTERNS_COMPILED)} attack patterns")

def should_ignore_ip(ip_str: str) -> bool:
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

def is_country_blocked(country_code: Optional[str]) -> bool:
    if not country_code:
        return False
    with _blocked_countries_lock:
        return country_code in _blocked_countries_cache

def calculate_threat_score(ip: str, path: str, is_attack: bool, status_code: int, login_attempt: bool) -> int:
    score = 0
    if is_attack:
        score += 30
        if any(p in path.lower() for p in ["sql", "union", "select", "drop"]):
            score += 20
        if any(p in path.lower() for p in ["exec", "eval", "system", "shell"]):
            score += 25
        if ".env" in path or ".git" in path:
            score += 15
    if login_attempt and status_code >= 400:
        score += 40
    if status_code == 404:
        score += 5
    if status_code >= 500:
        score += 10
    return min(score, 100)

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

RATE_LIMIT_THRESHOLD = int(os.getenv("RATE_LIMIT_THRESHOLD", "50"))

class LogHandler(FileSystemEventHandler):
    def __init__(self, geo, crowdsec=None):
        self.geo = geo
        self.crowdsec = crowdsec
        self.last_pos = 0
        self.blocked_ips_cache = set()
        self.whitelist_hosts = WHITELIST_HOSTS
        self.error_tracker = {}
        self.max_retries = 3

    def get_rate_limit_redis(self, ip: str) -> tuple[int, bool]:
        if redis_client:
            try:
                error_count = int(redis_client.hget(f"ratelimit:{ip}", "count") or 0)
                is_banned = redis_client.hget(f"ratelimit:{ip}", "banned") == "1"
                return error_count, is_banned
            except:
                pass
        return self.get_rate_limit_db(ip)

    def set_rate_limit_redis(self, ip: str, count: int, banned: bool = False):
        if redis_client:
            try:
                pipe = redis_client.pipeline()
                pipe.hset(f"ratelimit:{ip}", "count", str(count))
                pipe.hset(f"ratelimit:{ip}", "banned", "1" if banned else "0")
                pipe.expire(f"ratelimit:{ip}", 3600)
                pipe.execute()
                return True
            except:
                pass
        return self.set_rate_limit_db(ip, count, banned)

    def get_rate_limit_db(self, ip: str) -> tuple[int, bool]:
        session = SessionLocal()
        try:
            entry = session.query(RateLimitEntry).filter_by(ip_address=ip).first()
            if entry:
                return entry.error_count, entry.is_soft_banned
        finally:
            session.close()
        return 0, False

    def set_rate_limit_db(self, ip: str, count: int, banned: bool = False):
        session = SessionLocal()
        try:
            entry = session.query(RateLimitEntry).filter_by(ip_address=ip).first()
            if not entry:
                entry = RateLimitEntry(ip_address=ip)
                session.add(entry)
            entry.error_count = count
            entry.is_soft_banned = banned
            if banned:
                entry.ban_expires = datetime.now() + timedelta(hours=1)
            entry.last_error_time = datetime.now()
            session.commit()
        except Exception as e:
            logger.error(f"Rate limit DB error: {e}")
        finally:
            session.close()

    def check_rate_limit(self, ip: str, timestamp: datetime, host: str) -> bool:
        if host in self.whitelist_hosts:
            return False
        
        if is_country_blocked(self.geo.resolve(ip).get("country_code")):
            return True
            
        error_count, is_banned = self.get_rate_limit_redis(ip)
        
        if is_banned:
            return True
        
        error_count += 1
        self.set_rate_limit_redis(ip, error_count, error_count > RATE_LIMIT_THRESHOLD)
        
        return error_count > RATE_LIMIT_THRESHOLD

    def notify_discord(self, ip: str, reason: str, path: str, country_code: str):
        if not DISCORD_WEBHOOK: return
        try:
            payload = {
                "embeds": [{
                    "title": "🚨 God Mode Protection",
                    "description": f"IP `{ip}` blocked for malicious activity.",
                    "color": 0xFF0000,
                    "fields": [
                        {"name": "Reason", "value": reason, "inline": True},
                        {"name": "Path", "value": f"`{path}`", "inline": True},
                        {"name": "Country", "value": country_code or "Unknown", "inline": True}
                    ],
                    "timestamp": datetime.now().isoformat()
                }]
            }
            requests.post(DISCORD_WEBHOOK, json=payload, timeout=5)
        except Exception as e: logger.error(f"Discord error: {e}")

    def on_modified(self, event):
        if event.src_path == LOG_FILE: 
            self.process_new_lines()

    def clean_ip(self, addr: str) -> str:
        if not addr: return ""
        if ':' in addr:
            return addr.split(']')[0].replace('[', '') if addr.startswith('[') else addr.rsplit(':', 1)[0]
        return addr

    def is_attack(self, path: str) -> bool:
        if not path: return False
        if "remote.php" in path: return False
        for p in ATTACK_PATTERNS_COMPILED:
            if p.search(path): return True
        return False

    def is_login_attempt(self, path: str) -> bool:
        if not path: return False
        for p in LOGIN_PATTERNS_COMPILED:
            if p.search(path): return True
        return False

    def process_with_retry(self, func, *args, **kwargs):
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except OperationalError as e:
                logger.warning(f"DB error (attempt {attempt+1}/{self.max_retries}): {e}")
                time.sleep(0.5 * (attempt + 1))
                record_stat("db_errors", 1)
        return None

    def process_new_lines(self):
        start_time = time.time()
        session = SessionLocal()
        new_count = 0
        try:
            latest_db_entry = session.query(func.max(AccessLog.start_local)).scalar()
            
            if not os.path.exists(LOG_FILE):
                return
                
            if os.path.getsize(LOG_FILE) < self.last_pos:
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
                        
                        if should_ignore_ip(ip):
                            continue

                        geo_info = self.geo.resolve(ip)
                        
                        if is_country_blocked(geo_info.get("country_code")):
                            record_stat("attacks_detected", 1)
                            continue

                        ua = parse(log_data.RequestUserAgent)
                        path = log_data.RequestPath
                        host = log_data.RequestHost
                        
                        is_login = self.is_login_attempt(path)
                        attack = self.is_attack(path)
                        
                        if is_login:
                            login_attempt = LoginAttempt(
                                ip_address=ip,
                                path=path,
                                status_code=try_int(log_data.DownstreamStatus),
                                timestamp=log_time,
                                user_agent=log_data.RequestUserAgent,
                                country_code=geo_info.get("country_code")
                            )
                            session.add(login_attempt)
                        
                        reason = f"Attack pattern: {path}" if attack else None
                        
                        status_code = try_int(log_data.DownstreamStatus)
                        
                        if not attack and status_code >= 400:
                            if self.check_rate_limit(ip, log_time, host):
                                attack = True
                                reason = "Rate Limit Exceeded (High Error Rate)"
                        
                        threat_score = calculate_threat_score(ip, path, attack, status_code, is_login)
                        
                        if attack and self.crowdsec and ip not in self.blocked_ips_cache:
                            executor.submit(self.crowdsec.block_ip, ip, "24h", reason)
                            executor.submit(self.notify_discord, ip, reason, path, geo_info.get("country_code"))
                            self.blocked_ips_cache.add(ip)
                            record_stat("ips_banned", 1)
                        
                        log_entry = AccessLog(
                            start_local=log_time,
                            client_addr=ip,
                            country_code=geo_info.get("country_code"),
                            country_name=geo_info.get("country_name"),
                            city_name=geo_info.get("city"),
                            asn=geo_info.get("asn"),
                            request_method=log_data.RequestMethod,
                            request_path=path,
                            request_host=host,
                            request_protocol=log_data.RequestProtocol,
                            request_referer=log_data.RequestReferer,
                            request_user_agent=log_data.RequestUserAgent,
                            is_bot=ua.is_bot,
                            is_attack=attack,
                            is_login_attempt=is_login,
                            threat_score=threat_score,
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
                        record_stat("logs_processed", 1)
                        if attack:
                            record_stat("attacks_detected", 1)
                        
                        if new_count % 100 == 0:
                            try:
                                session.commit()
                            except Exception as e:
                                session.rollback()
                                logger.error(f"Batch commit error: {e}")
                                record_stat("db_errors", 1)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Error parsing log line: {e}")
                        continue
                
                self.last_pos = f.tell()
                
                try:
                    session.commit()
                except Exception as e:
                    session.rollback()
                    logger.error(f"Final batch commit error: {e}")
                    record_stat("db_errors", 1)
                
                if new_count > 0:
                    proc_time = (time.time() - start_time) * 1000 / max(new_count, 1)
                    record_stat("processing_time", proc_time)
                    logger.info(f"Processed {new_count} logs. Avg: {proc_time:.1f}ms/log")
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
        logger.info(f"Pruned {deleted} old logs")
    except Exception as e: logger.error(f"Prune Error: {e}")
    finally: session.close()

def prune_login_attempts():
    days = int(os.getenv("LOGIN_RETENTION_DAYS", "7"))
    if days <= 0: return
    cutoff = datetime.now() - timedelta(days=days)
    session = SessionLocal()
    try:
        deleted = session.query(LoginAttempt).filter(LoginAttempt.timestamp < cutoff).delete()
        session.commit()
    except Exception as e: logger.error(f"Prune login attempts: {e}")
    finally: session.close()

def notify_critical_error(err_msg: str):
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

def prometheus_metrics():
    metrics = []
    with STATS_LOCK:
        metrics.append(f"godmode_logs_processed_total {STATS['logs_processed']}")
        metrics.append(f"godmode_attacks_detected_total {STATS['attacks_detected']}")
        metrics.append(f"godmode_ips_banned_total {STATS['ips_banned']}")
        metrics.append(f"godmode_db_errors_total {STATS['db_errors']}")
        metrics.append(f"godmode_avg_processing_time_ms {get_avg_processing_time()}")
    return "\n".join(metrics)

def health_check() -> dict:
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "stats": dict(STATS),
        "uptime": time.time() - START_TIME
    }

START_TIME = time.time()

if __name__ == "__main__":
    try:
        init_db()
        load_blocked_countries()
    except Exception as e:
        logger.error(f"DB Init Error: {e}")
        notify_critical_error(f"DB Init Error: {e}")
        exit(1)
        
    geo = GeoResolver()
    crowdsec = CrowdSecManager()
    logger.info("Ultra Worker v2.0 started (Enhanced + Retry + Redis + Metrics)")
    
    handler = LogHandler(geo, crowdsec)
    handler.process_new_lines()
    
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE), recursive=False)
    observer.start()
    
    last_prune = time.time()
    last_stats_flush = time.time()
    last_pattern_reload = time.time()
    
    try:
        while True:
            time.sleep(30)
            handler.process_new_lines()
            
            current_time = time.time()
            
            if current_time - last_prune > 3600:
                prune_logs()
                prune_login_attempts()
                last_prune = current_time
            
            if current_time - last_stats_flush > 300:
                flush_stats()
                last_stats_flush = current_time
            
            if current_time - last_pattern_reload > 60:
                reload_attack_patterns()
                load_blocked_countries()
                last_pattern_reload = current_time
                
    except KeyboardInterrupt:
        observer.stop()
    except Exception as e:
        logger.error(f"Critical Worker Loop Error: {e}")
        notify_critical_error(f"Worker Loop Error: {e}")
        observer.stop()
    observer.join()