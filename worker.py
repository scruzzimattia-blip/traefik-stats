import os
import json
import time
import pandas as pd
from sqlalchemy import create_engine, Column, String, Integer, DateTime, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/traefik_stats")
LOG_FILE = "/app/logs/access.log"

Base = declarative_base()
class AccessLog(Base):
    __tablename__ = 'access_logs'
    id = Column(Integer, primary_key=True)
    start_local = Column(DateTime)
    client_addr = Column(String)
    request_method = Column(String)
    request_path = Column(String)
    request_host = Column(String)
    entry_point = Column(String)
    status_code = Column(Integer)
    duration = Column(Integer)
    __table_args__ = (UniqueConstraint('start_local', 'client_addr', 'request_path', name='_req_uc'),)

engine = create_engine(DB_URL)
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_pos = 0
        if os.path.exists(LOG_FILE):
            self.last_pos = os.path.getsize(LOG_FILE)

    def on_modified(self, event):
        if event.src_path == LOG_FILE:
            self.process_new_lines()

    def process_new_lines(self):
        session = Session()
        try:
            with open(LOG_FILE, 'r') as f:
                f.seek(self.last_pos)
                for line in f:
                    try:
                        data = json.loads(line)
                        log_entry = AccessLog(
                            start_local=pd.to_datetime(data.get('StartLocal')),
                            client_addr=data.get('ClientAddr'),
                            request_method=data.get('RequestMethod'),
                            request_path=data.get('RequestPath'),
                            request_host=data.get('RequestHost'),
                            entry_point=data.get('EntryPointName'),
                            status_code=int(data.get('DownstreamStatus', 0)),
                            duration=int(data.get('Duration', 0))
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
