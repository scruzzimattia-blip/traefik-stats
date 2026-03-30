import os
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime, BigInteger, Boolean, UniqueConstraint, Index, Text, Float, event
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger(__name__)

DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/traefik_stats")

Base = declarative_base()

# ============================================================================
# STRING FIELD LENGTH LIMITS
# ============================================================================
MAX_IP_LENGTH = 45
MAX_COUNTRY_CODE_LENGTH = 5
MAX_COUNTRY_NAME_LENGTH = 100
MAX_CITY_NAME_LENGTH = 100
MAX_ASN_LENGTH = 20
MAX_METHOD_LENGTH = 10
MAX_HOST_LENGTH = 255
MAX_PROTOCOL_LENGTH = 10
MAX_FAMILY_LENGTH = 50
MAX_ENTRYPOINT_LENGTH = 50
MAX_REASON_LENGTH = 200
MAX_STAT_TYPE_LENGTH = 50
MAX_PERIOD_LENGTH = 20
MAX_STAT_KEY_LENGTH = 200

class AccessLog(Base):
    """Web traffic access log entry with geo, security and performance data."""
    __tablename__ = 'access_logs'
    
    id = Column(Integer, primary_key=True)
    start_local = Column(DateTime, index=True)
    client_addr = Column(String(MAX_IP_LENGTH), index=True)
    
    # Geo Data
    country_code = Column(String(MAX_COUNTRY_CODE_LENGTH), index=True)
    country_name = Column(String(MAX_COUNTRY_NAME_LENGTH))
    city_name = Column(String(MAX_CITY_NAME_LENGTH))
    asn = Column(String(MAX_ASN_LENGTH), index=True)
    
    # Request Data
    request_method = Column(String(MAX_METHOD_LENGTH), index=True)
    request_path = Column(String)  # Path can be long, no limit enforced
    request_host = Column(String(MAX_HOST_LENGTH), index=True)
    request_protocol = Column(String(MAX_PROTOCOL_LENGTH))
    request_referer = Column(String)  # Can be long
    request_user_agent = Column(String)  # Can be long
    
    # Bot & Security Detection
    is_bot = Column(Boolean, default=False, index=True)
    is_attack = Column(Boolean, default=False, index=True)
    is_login_attempt = Column(Boolean, default=False, index=True)
    threat_score = Column(Integer, default=0, index=True)
    browser_family = Column(String(MAX_FAMILY_LENGTH), index=True)
    os_family = Column(String(MAX_FAMILY_LENGTH), index=True)
    device_family = Column(String(MAX_FAMILY_LENGTH), index=True)

    # Traefik Data
    entry_point = Column(String(MAX_ENTRYPOINT_LENGTH), index=True)
    status_code = Column(Integer, index=True)
    duration = Column(BigInteger, index=True)
    content_size = Column(BigInteger, index=True)
    
    __table_args__ = (
        UniqueConstraint('start_local', 'client_addr', 'request_path', 'request_method', name='_req_uc'),
        Index('idx_host_status', 'request_host', 'status_code'),
        Index('idx_time_host', 'start_local', 'request_host'),
        Index('idx_attack_time', 'is_attack', 'start_local'),
    )

class RateLimitEntry(Base):
    """IP-based rate limiting entry with soft ban tracking."""
    __tablename__ = 'rate_limits'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(MAX_IP_LENGTH), unique=True, index=True)
    error_count = Column(Integer, default=0)
    last_error_time = Column(DateTime)
    is_soft_banned = Column(Boolean, default=False)
    ban_expires = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

class LoginAttempt(Base):
    """Tracks attempted logins for brute-force detection."""
    __tablename__ = 'login_attempts'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(MAX_IP_LENGTH), index=True)
    path = Column(String)
    status_code = Column(Integer)
    timestamp = Column(DateTime, default=datetime.now, index=True)
    user_agent = Column(String)  # Can be long
    country_code = Column(String(MAX_COUNTRY_CODE_LENGTH))

class BlockedCountry(Base):
    """Geo-blocking rules for country-level IP filtering."""
    __tablename__ = 'blocked_countries'
    
    id = Column(Integer, primary_key=True)
    country_code = Column(String(MAX_COUNTRY_CODE_LENGTH), unique=True)
    reason = Column(String(MAX_REASON_LENGTH))
    added_at = Column(DateTime, default=datetime.now)
    active = Column(Boolean, default=True)

class WorkerStats(Base):
    """Worker process statistics snapshot for monitoring."""
    __tablename__ = 'worker_stats'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now, index=True)
    logs_processed = Column(Integer, default=0)
    attacks_detected = Column(Integer, default=0)
    ips_banned = Column(Integer, default=0)
    db_errors = Column(Integer, default=0)
    avg_processing_time_ms = Column(Float, default=0)

class PrecomputedStats(Base):
    """Cached aggregated statistics for faster dashboard queries."""
    __tablename__ = 'precomputed_stats'
    
    id = Column(Integer, primary_key=True)
    stat_type = Column(String(MAX_STAT_TYPE_LENGTH), index=True)
    period = Column(String(MAX_PERIOD_LENGTH))
    key = Column(String(MAX_STAT_KEY_LENGTH))
    value = Column(Float)
    updated_at = Column(DateTime, default=datetime.now, index=True)
    
    __table_args__ = (
        Index('idx_stat_period', 'stat_type', 'period'),
    )

engine_args = {"pool_pre_ping": True}
if not DB_URL.startswith("sqlite"):
    engine_args.update({"pool_size": 10, "max_overflow": 20})

engine = create_engine(DB_URL, **engine_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    migrate_new_columns()

ALLOWED_COLUMNS = {
    "is_login_attempt": "BOOLEAN DEFAULT FALSE",
    "threat_score": "INTEGER DEFAULT 0"
}

def migrate_new_columns():
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            for col_name, col_def in ALLOWED_COLUMNS.items():
                if not col_name.replace("_", "").isalnum():
                    continue
                try:
                    conn.execute(text(f"ALTER TABLE access_logs ADD COLUMN {col_name} {col_def}"))
                    conn.commit()
                except Exception:
                    pass
    except Exception as e:
        logger.warning(f"Migration check skipped: {e}")
