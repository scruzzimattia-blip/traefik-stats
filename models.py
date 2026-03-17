import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime, BigInteger, Boolean, UniqueConstraint, Index, Text, Float
from sqlalchemy.orm import sessionmaker, declarative_base

DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/traefik_stats")

Base = declarative_base()

class AccessLog(Base):
    __tablename__ = 'access_logs'
    
    id = Column(Integer, primary_key=True)
    start_local = Column(DateTime, index=True)
    client_addr = Column(String, index=True)
    
    # Geo Data
    country_code = Column(String(5), index=True)
    country_name = Column(String(100))
    city_name = Column(String(100))
    asn = Column(String(20), index=True)
    
    # Request Data
    request_method = Column(String(10), index=True)
    request_path = Column(String)
    request_host = Column(String, index=True)
    request_protocol = Column(String(10))
    request_referer = Column(String)
    request_user_agent = Column(String)
    
    # Bot & Security Detection
    is_bot = Column(Boolean, default=False, index=True)
    is_attack = Column(Boolean, default=False, index=True)
    is_login_attempt = Column(Boolean, default=False, index=True)
    threat_score = Column(Integer, default=0, index=True)
    browser_family = Column(String(50), index=True)
    os_family = Column(String(50), index=True)
    device_family = Column(String(50), index=True)

    # Traefik Data
    entry_point = Column(String(50), index=True)
    status_code = Column(Integer, index=True)
    duration = Column(BigInteger, index=True)
    content_size = Column(BigInteger, index=True)
    
    __table_args__ = (
        UniqueConstraint('start_local', 'client_addr', 'request_path', 'request_method', name='_req_uc'),
        Index('idx_host_status', 'request_host', 'status_code'),
        Index('idx_time_host', 'start_local', 'request_host'),
    )

class RateLimitEntry(Base):
    __tablename__ = 'rate_limits'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, index=True)
    error_count = Column(Integer, default=0)
    last_error_time = Column(DateTime)
    is_soft_banned = Column(Boolean, default=False)
    ban_expires = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

class LoginAttempt(Base):
    __tablename__ = 'login_attempts'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), index=True)
    path = Column(String)
    status_code = Column(Integer)
    timestamp = Column(DateTime, default=datetime.now, index=True)
    user_agent = Column(String)
    country_code = Column(String(5))

class BlockedCountry(Base):
    __tablename__ = 'blocked_countries'
    
    id = Column(Integer, primary_key=True)
    country_code = Column(String(5), unique=True)
    reason = Column(String(200))
    added_at = Column(DateTime, default=datetime.now)
    active = Column(Boolean, default=True)

class WorkerStats(Base):
    __tablename__ = 'worker_stats'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now, index=True)
    logs_processed = Column(Integer, default=0)
    attacks_detected = Column(Integer, default=0)
    ips_banned = Column(Integer, default=0)
    db_errors = Column(Integer, default=0)
    avg_processing_time_ms = Column(Float, default=0)

class PrecomputedStats(Base):
    __tablename__ = 'precomputed_stats'
    
    id = Column(Integer, primary_key=True)
    stat_type = Column(String(50), index=True)
    period = Column(String(20))
    key = Column(String(200))
    value = Column(Float)
    updated_at = Column(DateTime, default=datetime.now, index=True)
    
    __table_args__ = (
        Index('idx_stat_period', 'stat_type', 'period'),
    )

engine = create_engine(DB_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
