import streamlit as st
import pandas as pd
import plotly.express as px
from models import engine, AccessLog
from sqlalchemy import select, func
from datetime import datetime, timedelta

st.set_page_config(page_title="Traefik Advanced Dashboard", layout="wide", page_icon="🚀")

st.title("🚀 Traefik Advanced Traffic Dashboard")

def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

@st.cache_data(ttl=30)
def fetch_data():
    query = select(AccessLog).order_by(AccessLog.start_local.desc())
    df = pd.read_sql(query, engine)
    if not df.empty:
        df['start_local'] = pd.to_datetime(df['start_local'])
        df['duration_ms'] = df['duration'] / 1_000_000 # ns to ms
    return df

df = fetch_data()

if df.empty:
    st.warning("No traffic data found in PostgreSQL. Please check if the worker is running.")
    if st.button("🔄 Refresh"):
        st.rerun()
else:
    # Sidebar Filters
    st.sidebar.header("🔍 Global Filters")
    time_range = st.sidebar.selectbox("Time Range", ["All", "Last 24h", "Last 7d", "Last 30d"])
    
    now = datetime.now()
    if time_range == "Last 24h":
        df = df[df['start_local'] > (now - timedelta(days=1))]
    elif time_range == "Last 7d":
        df = df[df['start_local'] > (now - timedelta(days=7))]
    elif time_range == "Last 30d":
        df = df[df['start_local'] > (now - timedelta(days=30))]

    hosts = st.sidebar.multiselect("Filter Hosts", options=df['request_host'].unique(), default=df['request_host'].unique())
    df = df[df['request_host'].isin(hosts)]

    # Layout with Tabs
    tab_overview, tab_traffic, tab_security, tab_clients = st.tabs(["📊 Overview", "📡 Traffic Details", "🛡️ Security & Errors", "💻 Clients & UAs"])

    with tab_overview:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Requests", len(df))
        
        total_bw = df['content_size'].sum()
        c2.metric("Bandwidth Used", format_bytes(total_bw))
        
        avg_dur = df['duration_ms'].mean()
        c3.metric("Avg Latency", f"{avg_dur:.2f} ms")
        
        success_rate = (df['status_code'] < 400).mean() * 100
        c4.metric("Success Rate", f"{success_rate:.1f}%")

        st.subheader("Traffic Timeline (Requests per min)")
        df_resampled = df.set_index('start_local').resample('1min').size().reset_index(name='count')
        fig_timeline = px.line(df_resampled, x='start_local', y='count', color_discrete_sequence=['#00CC96'])
        st.plotly_chart(fig_timeline, use_container_width=True)

    with tab_traffic:
        col_left, col_right = st.columns(2)
        
        with col_left:
            st.subheader("Requests per Service (Host)")
            host_counts = df['request_host'].value_counts().reset_index()
            host_counts.columns = ['Host', 'Count']
            fig_hosts = px.bar(host_counts, x='Count', y='Host', orientation='h', color='Count')
            st.plotly_chart(fig_hosts, use_container_width=True)
        
        with col_right:
            st.subheader("Top Paths")
            path_counts = df['request_path'].value_counts().head(15).reset_index()
            path_counts.columns = ['Path', 'Count']
            fig_paths = px.bar(path_counts, x='Count', y='Path', orientation='h')
            st.plotly_chart(fig_paths, use_container_width=True)

        st.subheader("Latency Heatmap (ms)")
        fig_lat = px.histogram(df, x='duration_ms', nbins=50, title="Latency Distribution", color_discrete_sequence=['#AB63FA'])
        st.plotly_chart(fig_lat, use_container_width=True)

    with tab_security:
        col_s1, col_s2 = st.columns(2)
        
        with col_s1:
            st.subheader("HTTP Status Codes")
            status_dist = df['status_code'].value_counts().reset_index()
            status_dist.columns = ['Status', 'Count']
            fig_status = px.pie(status_dist, names='Status', values='Count', hole=0.4, 
                                color_discrete_sequence=px.colors.qualitative.Set3)
            st.plotly_chart(fig_status, use_container_width=True)

        with col_s2:
            st.subheader("Non-200/300 Response Paths")
            errors_df = df[df['status_code'] >= 400]
            if not errors_df.empty:
                error_paths = errors_df['request_path'].value_counts().head(10).reset_index()
                error_paths.columns = ['Path', 'Count']
                st.table(error_paths)
            else:
                st.info("No errors detected in selected range.")

    with tab_clients:
        col_c1, col_c2 = st.columns(2)
        
        with col_c1:
            st.subheader("Top Clients (IP)")
            top_ips = df['client_addr'].value_counts().head(15).reset_index()
            top_ips.columns = ['IP', 'Requests']
            st.dataframe(top_ips, use_container_width=True)

        with col_c2:
            st.subheader("Top User Agents")
            top_uas = df['request_user_agent'].value_counts().head(15).reset_index()
            top_uas.columns = ['User Agent', 'Count']
            st.dataframe(top_uas, use_container_width=True)

        st.subheader("Top Referrers")
        top_referrers = df['request_referer'].value_counts().head(10).reset_index()
        top_referrers.columns = ['Referer', 'Count']
        st.table(top_referrers)

    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Refresh Data"):
        st.rerun()
