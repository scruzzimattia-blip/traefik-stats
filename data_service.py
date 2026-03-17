import pandas as pd
from sqlalchemy import select
from models import engine, AccessLog
import streamlit as st

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
