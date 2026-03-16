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

# Query data from Postgres
query = "SELECT * FROM access_logs ORDER BY start_local DESC"
try:
    df = pd.read_sql(query, engine)
except Exception:
    df = pd.DataFrame()

if df.empty:
    st.warning("No data in database. Ensure the worker is running and Traefik is logging.")
    if st.button("Refresh"):
        st.rerun()
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
    
    if st.button("Refresh"):
        st.rerun()
