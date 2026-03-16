import streamlit as st
import pandas as pd
import json
import plotly.express as px
from sqlalchemy import create_engine, Column, String, Integer, DateTime, UniqueConstraint, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import time

st.set_page_config(page_title="Traefik Stats (DB)", layout="wide")

st.title("📊 Traefik Stats - PostgreSQL")

# Database Configuration
DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/traefik_stats")
LOG_FILE = "/app/logs/access.log"

# SQLAlchemy setup
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

def load_logs_to_db():
    if not os.path.exists(LOG_FILE):
        return 0
    
    session = Session()
    new_records = 0
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # Simple duplicate check before inserting
                    # Traefik logs usually have StartLocal
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
                    new_records += 1
                except Exception:
                    session.rollback()
                    continue
    finally:
        session.close()
    return new_records

# Sidebar: Actions & Info
if st.sidebar.button("🔄 Import New Logs"):
    n = load_logs_to_db()
    st.sidebar.success(f"Imported {n} new records.")

# Query data from Postgres
query = "SELECT * FROM access_logs ORDER BY start_local DESC"
df = pd.read_sql(query, engine)

if df.empty:
    st.warning("No data in database. Try 'Import New Logs' or check access.log.")
else:
    # Sidebar filters
    st.sidebar.header("Filters")
    entry_point = st.sidebar.multiselect("Entry Point", options=df['entry_point'].unique(), default=df['entry_point'].unique())
    methods = st.sidebar.multiselect("Method", options=df['request_method'].unique(), default=df['request_method'].unique())
    
    filtered_df = df[df['entry_point'].isin(entry_point) & df['request_method'].isin(methods)]

    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", len(filtered_df))
    success_rate = (filtered_df['status_code'] < 400).mean() * 100
    col2.metric("Success Rate", f"{success_rate:.1f}%")
    col3.metric("Errors (4xx/5xx)", len(filtered_df[filtered_df['status_code'] >= 400]))
    avg_duration = filtered_df['duration'].mean() / 1_000_000
    col4.metric("Avg Duration", f"{avg_duration:.2f}ms")

    # Timeline Chart
    st.subheader("Requests over Time")
    df_time = filtered_df.set_index('start_local').resample('1min').size().reset_index(name='count')
    fig_time = px.line(df_time, x='start_local', y='count')
    st.plotly_chart(fig_time, use_container_width=True)

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Status Codes")
        fig_status = px.pie(filtered_df, names='status_code')
        st.plotly_chart(fig_status, use_container_width=True)
    with c2:
        st.subheader("Top Hosts")
        top_hosts = filtered_df['request_host'].value_counts().head(10).reset_index()
        top_hosts.columns = ['Host', 'Count']
        fig_hosts = px.bar(top_hosts, x='Count', y='Host', orientation='h')
        st.plotly_chart(fig_hosts, use_container_width=True)

    st.subheader("Latest Requests")
    st.dataframe(filtered_df.head(20))
