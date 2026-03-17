import os
from sqlalchemy import create_engine, Column, String, Integer, DateTime, BigInteger, Boolean, UniqueConstraint, Index
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
    country_name = Column(String(100)) # Full Name for Maps
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
    browser_family = Column(String(50), index=True)
    os_family = Column(String(50), index=True)
    device_family = Column(String(50), index=True)

    # Traefik Data
    entry_point = Column(String(50), index=True)
    status_code = Column(Integer, index=True)
    duration = Column(BigInteger, index=True) # ns
    content_size = Column(BigInteger, index=True) # bytes
    
    __table_args__ = (
        UniqueConstraint('start_local', 'client_addr', 'request_path', 'request_method', name='_req_uc'),
        Index('idx_host_status', 'request_host', 'status_code'),
        Index('idx_time_host', 'start_local', 'request_host'),
    )

engine = create_engine(
    DB_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
