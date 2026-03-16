import os
import json
import time
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from models import init_db, SessionLocal, AccessLog

LOG_FILE = "/app/logs/access.log"

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_pos = 0
        if os.path.exists(LOG_FILE):
            self.last_pos = os.path.getsize(LOG_FILE)

    def on_modified(self, event):
        if event.src_path == LOG_FILE:
            self.process_new_lines()

    def process_new_lines(self):
        session = SessionLocal()
        try:
            with open(LOG_FILE, 'r') as f:
                f.seek(self.last_pos)
                for line in f:
                    try:
                        data = json.loads(line)
                        
                        # Clean IP address (strip port)
                        client_addr = data.get('ClientAddr', '')
                        if ':' in client_addr:
                            if client_addr.startswith('['):
                                # IPv6 format: [2001:db8::1]:12345
                                client_addr = client_addr.split(']')[0].replace('[', '')
                            else:
                                # IPv4 format: 1.2.3.4:12345
                                client_addr = client_addr.rsplit(':', 1)[0]

                        log_entry = AccessLog(
                            start_local=pd.to_datetime(data.get('StartLocal')),
                            client_addr=client_addr,
                            request_method=data.get('RequestMethod'),
                            request_path=data.get('RequestPath'),
                            request_host=data.get('RequestHost'),
                            request_protocol=data.get('RequestProtocol'),
                            request_referer=data.get('RequestReferer'),
                            request_user_agent=data.get('RequestUserAgent'),
                            entry_point=data.get('EntryPointName'),
                            status_code=int(data.get('DownstreamStatus', 0)),
                            duration=int(data.get('Duration', 0)),
                            content_size=int(data.get('DownstreamContentSize', 0))
                        )
                        session.add(log_entry)
                        session.commit()
                    except Exception:
                        session.rollback()
                        continue
                self.last_pos = f.tell()
        finally:
            session.close()

if __name__ == "__main__":
    init_db()
    print(f"Starting worker, monitoring {LOG_FILE}...")
    
    # Initial processing of existing logs
    handler = LogHandler()
    handler.last_pos = 0 # Start from beginning on first run
    handler.process_new_lines()
    
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
