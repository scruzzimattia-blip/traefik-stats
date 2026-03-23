import pandas as pd
import streamlit as st
import requests
import os
from datetime import datetime, timedelta
import logging
from models import engine, AccessLog, SessionLocal, LoginAttempt, BlockedCountry, WorkerStats, PrecomputedStats
from sqlalchemy import func, select, and_, or_
from cache_service import CacheService, cached

logger = logging.getLogger(__name__)

@cached(ttl=60, key_prefix="fetch_data")
def fetch_data(limit=50000):
    try:
        query = select(AccessLog).order_by(AccessLog.start_local.desc()).limit(limit)
        df = pd.read_sql(query, engine)
        if not df.empty:
            df['start_local'] = pd.to_datetime(df['start_local'])
            df['duration_ms'] = df['duration'] / 1_000_000
            df['status_group'] = df['status_code'].apply(lambda x: f"{str(x)[0]}xx")
        return df
    except Exception as e: 
        st.error(f"DB Error: {e}")
        return pd.DataFrame()

@cached(ttl=300, key_prefix="precomputed_stats")
def fetch_precomputed_stats(stat_type: str, period: str = "24h") -> dict:
    try:
        stats = SessionLocal().query(PrecomputedStats).filter(
            PrecomputedStats.stat_type == stat_type,
            PrecomputedStats.period == period
        ).all()
        return {s.key: s.value for s in stats}
    except:
        return {}

def update_precomputed_stats():
    session = SessionLocal()
    try:
        now = datetime.now()
        cutoff_5m = now - timedelta(minutes=5)
        cutoff_1h = now - timedelta(hours=1)
        cutoff_24h = now - timedelta(days=1)
        
        for period, cutoff in [("5m", cutoff_5m), ("1h", cutoff_1h), ("24h", cutoff_24h)]:
            requests_by_host = session.query(
                AccessLog.request_host,
                func.count(AccessLog.id).label('count')
            ).filter(AccessLog.start_local > cutoff).group_by(AccessLog.request_host).all()
            
            for host, count in requests_by_host:
                existing = session.query(PrecomputedStats).filter(
                    PrecomputedStats.stat_type == "requests_by_host",
                    PrecomputedStats.period == period,
                    PrecomputedStats.key == host
                ).first()
                if existing:
                    existing.value = count
                    existing.updated_at = now
                else:
                    session.add(PrecomputedStats(stat_type="requests_by_host", period=period, key=host, value=count))
            
            avg_latency = session.query(
                AccessLog.request_path,
                func.avg(AccessLog.duration / 1_000_000).label('avg_ms')
            ).filter(AccessLog.start_local > cutoff).group_by(AccessLog.request_path).all()
            
            for path, avg_ms in avg_latency:
                if avg_ms:
                    existing = session.query(PrecomputedStats).filter(
                        PrecomputedStats.stat_type == "avg_latency",
                        PrecomputedStats.period == period,
                        PrecomputedStats.key == path
                    ).first()
                    if existing:
                        existing.value = float(avg_ms)
                        existing.updated_at = now
                    else:
                        session.add(PrecomputedStats(stat_type="avg_latency", period=period, key=path, value=float(avg_ms)))
        
        session.commit()
        CacheService.delete_pattern("traefik_stats:fetch_data:*")
        CacheService.delete_pattern("traefik_stats:precomputed_stats:*")
    except Exception as e:
        logger.error(f"Precompute error: {e}")
    finally:
        session.close()



def format_bytes(size):
    if size is None: return "0 B"
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T', 5: 'P'}
    while size > power and n < 5:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

@cached(ttl=3600, key_prefix="abuse_reputation")
def get_abuse_reputation(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return None
        
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            return response.json().get('data')
    except Exception:
        pass
    return None

def get_total_logs_count(filter_attack=False):
    cache_key = f"traefik_stats:logs_count:{filter_attack}"
    cached = CacheService.get(cache_key)
    if cached is not None:
        return cached
    
    try:
        session = SessionLocal()
        query = session.query(func.count(AccessLog.id))
        if filter_attack:
            query = query.filter(AccessLog.is_attack == True)
        count = query.scalar()
        session.close()
        CacheService.set(cache_key, count, ttl=30)
        return count
    except Exception as e:
        st.error(f"Error counting logs: {e}")
        return 0

def fetch_logs_paginated(limit=50, offset=0, filter_attack=False, filter_login=False):
    try:
        query = select(AccessLog).order_by(AccessLog.start_local.desc()).limit(limit).offset(offset)
        if filter_attack:
            query = query.where(AccessLog.is_attack == True)
        if filter_login:
            query = query.where(AccessLog.is_login_attempt == True)
            
        df = pd.read_sql(query, engine)
        if not df.empty:
            df['start_local'] = pd.to_datetime(df['start_local'])
            df['duration_ms'] = df['duration'] / 1_000_000
            df['status_group'] = df['status_code'].apply(lambda x: f"{str(x)[0]}xx")
        return df
    except Exception as e:
        st.error(f"Error fetching paginated logs: {e}")
        return pd.DataFrame()

def get_login_attempts(hours=24, limit=100):
    try:
        session = SessionLocal()
        cutoff = datetime.now() - timedelta(hours=hours)
        attempts = session.query(LoginAttempt).filter(
            LoginAttempt.timestamp > cutoff
        ).order_by(LoginAttempt.timestamp.desc()).limit(limit).all()
        session.close()
        return attempts
    except Exception as e:
        logger.error(f"Login attempts error: {e}")
        return []

def get_top_slowest_endpoints(limit=20):
    try:
        query = select(
            AccessLog.request_path,
            func.avg(AccessLog.duration / 1_000_000).label('avg_ms'),
            func.count(AccessLog.id).label('hits')
        ).group_by(AccessLog.request_path).order_by(func.avg(AccessLog.duration / 1_000_000).desc()).limit(limit)
        return pd.read_sql(query, engine)
    except Exception as e:
        logger.error(f"Slowest endpoints error: {e}")
        return pd.DataFrame()

def get_error_trends(hours=24):
    try:
        cutoff = datetime.now() - timedelta(hours=hours)
        query = select(
            func.date_trunc('hour', AccessLog.start_local).label('hour'),
            AccessLog.status_code,
            func.count(AccessLog.id).label('count')
        ).filter(AccessLog.start_local > cutoff, AccessLog.status_code >= 400).group_by('hour', AccessLog.status_code).order_by('hour')
        return pd.read_sql(query, engine)
    except Exception as e:
        logger.error(f"Error trends error: {e}")
        return pd.DataFrame()

def get_bandwidth_spikes(hours=24):
    try:
        cutoff = datetime.now() - timedelta(hours=hours)
        query = select(
            func.date_trunc('minute', AccessLog.start_local).label('minute'),
            func.sum(AccessLog.content_size).label('bytes')
        ).filter(AccessLog.start_local > cutoff).group_by('minute').order_by('bytes desc').limit(20)
        return pd.read_sql(query, engine)
    except Exception as e:
        logger.error(f"Bandwidth spikes error: {e}")
        return pd.DataFrame()

def get_threat_leaders(limit=20):
    cache_key = f"traefik_stats:threat_leaders:{limit}"
    cached = CacheService.get(cache_key)
    if cached is not None:
        return pd.DataFrame(cached) if cached else pd.DataFrame()
    
    try:
        from crowdsec import CrowdSecManager
        cs = CrowdSecManager()
        blocked_ips = {d.get('value') for d in cs.get_all_decisions() if d.get('value')}
        
        query = select(
            AccessLog.client_addr,
            func.sum(AccessLog.threat_score).label('total_threat'),
            func.count(AccessLog.id).label('requests'),
            AccessLog.country_code,
            AccessLog.asn
        ).group_by(AccessLog.client_addr, AccessLog.country_code, AccessLog.asn).order_by(func.sum(AccessLog.threat_score).desc())
        
        df = pd.read_sql(query, engine)
        
        if blocked_ips:
            df = df[~df['client_addr'].isin(blocked_ips)]
        
        result = df.head(limit).to_dict('records')
        CacheService.set(cache_key, result, ttl=300)
        return df.head(limit)
    except Exception as e:
        logger.error(f"Threat leaders error: {e}")
        return pd.DataFrame()

def get_blocked_countries():
    cache_key = "traefik_stats:blocked_countries"
    cached = CacheService.get(cache_key)
    if cached is not None:
        return [BlockedCountry(**c) for c in cached] if cached else []
    
    try:
        countries = SessionLocal().query(BlockedCountry).all()
        countries_data = [{"id": c.id, "country_code": c.country_code, "reason": c.reason, "added_at": c.added_at, "active": c.active} for c in countries]
        CacheService.set(cache_key, countries_data, ttl=60)
        return countries
    except:
        return []

def add_blocked_country(country_code: str, reason: str = ""):
    session = SessionLocal()
    try:
        existing = session.query(BlockedCountry).filter_by(country_code=country_code.upper()).first()
        if not existing:
            blocked = BlockedCountry(country_code=country_code.upper(), reason=reason, active=True)
            session.add(blocked)
            session.commit()
            CacheService.delete("traefik_stats:blocked_countries")
            return True
    except Exception as e:
        logger.error(f"Block country error: {e}")
    finally:
        session.close()
    return False

def remove_blocked_country(country_code: str):
    session = SessionLocal()
    try:
        entry = session.query(BlockedCountry).filter_by(country_code=country_code.upper()).first()
        if entry:
            entry.active = False
            session.commit()
            CacheService.delete("traefik_stats:blocked_countries")
            return True
    except Exception as e:
        logger.error(f"Remove block error: {e}")
    finally:
        session.close()
    return False

def get_worker_stats(hours=24):
    try:
        cutoff = datetime.now() - timedelta(hours=hours)
        stats = SessionLocal().query(WorkerStats).filter(WorkerStats.timestamp > cutoff).all()
        return [{
            "timestamp": s.timestamp,
            "logs_processed": s.logs_processed,
            "attacks_detected": s.attacks_detected,
            "ips_banned": s.ips_banned,
            "db_errors": s.db_errors,
            "avg_processing_time_ms": s.avg_processing_time_ms
        } for s in stats]
    except:
        return []