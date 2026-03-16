import os
import json
import time
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from models import init_db, SessionLocal, AccessLog
from user_agents import parse
import logging
import maxminddb
from datetime import datetime, timedelta

LOG_FILE = "/app/logs/access.log"
CITY_DB = "/app/geoip/city.mmdb"
ASN_DB = "/app/geoip/asn.mmdb"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GeoResolver:
    def __init__(self):
        self.city_reader = None
        self.asn_reader = None
        try:
            if os.path.exists(CITY_DB):
                self.city_reader = maxminddb.open_database(CITY_DB)
            if os.path.exists(ASN_DB):
                self.asn_reader = maxminddb.open_database(ASN_DB)
        except Exception as e:
            logger.error(f"GeoIP Load Error: {e}")

    def resolve(self, ip):
        res = {"country": None, "city": None, "asn": None}
        if not ip: return res
        try:
            if self.city_reader:
                match = self.city_reader.get(ip)
                if match:
                    res["country"] = match.get('country', {}).get('iso_code')
                    res["city"] = match.get('city', {}).get('names', {}).get('en')
            if self.asn_reader:
                match = self.asn_reader.get(ip)
                if match:
                    res["asn"] = f"AS{match.get('autonomous_system_number')}"
        except: pass
        return res

class LogHandler(FileSystemEventHandler):
    def __init__(self, geo):
        self.geo = geo
        self.last_pos = 0
        if os.path.exists(LOG_FILE):
            self.last_pos = os.path.getsize(LOG_FILE)

    def on_modified(self, event):
        if event.src_path == LOG_FILE: self.process_new_lines()

    def clean_ip(self, addr):
        if not addr: return ""
        if ':' in addr:
            return addr.split(']')[0].replace('[', '') if addr.startswith('[') else addr.rsplit(':', 1)[0]
        return addr

    def process_new_lines(self):
        session = SessionLocal()
        try:
            with open(LOG_FILE, 'r') as f:
                f.seek(self.last_pos)
                for line in f:
                    try:
                        data = json.loads(line)
                        ip = self.clean_ip(data.get('ClientAddr', ''))
                        geo_info = self.geo.resolve(ip)
                        ua = parse(data.get('RequestUserAgent', ''))
                        
                        session.add(AccessLog(
                            start_local=pd.to_datetime(data.get('StartLocal')),
                            client_addr=ip,
                            country_code=geo_info["country"],
                            city_name=geo_info["city"],
                            asn=geo_info["asn"],
                            request_method=data.get('RequestMethod'),
                            request_path=data.get('RequestPath'),
                            request_host=data.get('RequestHost'),
                            request_protocol=data.get('RequestProtocol'),
                            request_referer=data.get('RequestReferer'),
                            request_user_agent=data.get('RequestUserAgent'),
                            is_bot=ua.is_bot,
                            browser_family=ua.browser.family,
                            os_family=ua.os.family,
                            device_family=ua.device.family,
                            entry_point=data.get('EntryPointName'),
                            status_code=int(data.get('DownstreamStatus', 0)),
                            duration=int(data.get('Duration', 0)),
                            content_size=int(data.get('DownstreamContentSize', 0))
                        ))
                        session.commit()
                    except:
                        session.rollback()
                self.last_pos = f.tell()
        finally:
            session.close()

def prune_logs():
    days = int(os.getenv("RETENTION_DAYS", "30"))
    cutoff = datetime.now() - timedelta(days=days)
    session = SessionLocal()
    try:
        deleted = session.query(AccessLog).filter(AccessLog.start_local < cutoff).delete()
        session.commit()
        if deleted: logger.info(f"Pruned {deleted} old log entries.")
    except Exception as e:
        logger.error(f"Prune Error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    init_db()
    geo = GeoResolver()
    logger.info("Worker started with GeoIP and Auto-Pruning.")
    
    handler = LogHandler(geo)
    handler.last_pos = 0
    handler.process_new_lines()
    
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE), recursive=False)
    observer.start()
    
    last_prune = time.time()
    try:
        while True:
            if time.time() - last_prune > 3600: # Every hour
                prune_logs()
                last_prune = time.time()
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
