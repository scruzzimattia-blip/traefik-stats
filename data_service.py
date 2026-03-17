import pandas as pd
import streamlit as st
import requests
import os
from models import engine, AccessLog, SessionLocal
from sqlalchemy import func, select

@st.cache_data(ttl=5)
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

@st.cache_data(ttl=3600)
def get_abuse_reputation(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return None
        
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            return response.json().get('data')
    except Exception:
        pass
    return None

def get_total_logs_count(filter_attack=False):
    """Gibt die Gesamtanzahl der Logs in der DB zurück."""
    try:
        from sqlalchemy import func
        session = SessionLocal()
        query = session.query(func.count(AccessLog.id))
        if filter_attack:
            query = query.filter(AccessLog.is_attack == True)
        count = query.scalar()
        session.close()
        return count
    except Exception as e:
        st.error(f"Error counting logs: {e}")
        return 0

def fetch_logs_paginated(limit=50, offset=0, filter_attack=False):
    """Ruft einen spezifischen Block an Logs ab (Pagination)."""
    try:
        query = select(AccessLog).order_by(AccessLog.start_local.desc()).limit(limit).offset(offset)
        if filter_attack:
            query = query.where(AccessLog.is_attack == True)
            
        df = pd.read_sql(query, engine)
        if not df.empty:
            df['start_local'] = pd.to_datetime(df['start_local'])
            df['duration_ms'] = df['duration'] / 1_000_000
            df['status_group'] = df['status_code'].apply(lambda x: f"{str(x)[0]}xx")
        return df
    except Exception as e:
        st.error(f"Error fetching paginated logs: {e}")
        return pd.DataFrame()
