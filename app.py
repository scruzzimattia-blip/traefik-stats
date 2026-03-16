import streamlit as st
import pandas as pd
import plotly.express as px
from models import engine, AccessLog
from sqlalchemy import select
from datetime import datetime, timedelta

st.set_page_config(page_title="Traefik Ultimate Monitor Pro+", layout="wide", page_icon="🌐")

st.markdown("""
<style>
    [data-testid="stMetric"] { border: 1px solid rgba(255, 255, 255, 0.1); padding: 1rem; border-radius: 0.5rem; background: rgba(255, 255, 255, 0.05); }
    .stTabs [data-baseweb="tab-list"] { gap: 10px; }
    .stTabs [data-baseweb="tab"] { border-radius: 6px 6px 0px 0px; padding: 10px 20px; background-color: rgba(255, 255, 255, 0.03); }
    .stTabs [aria-selected="true"] { color: #00CC96; border-bottom: 2px solid #00CC96; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Traefik Ultimate Monitor Pro+")

def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0: return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

@st.cache_data(ttl=10)
def fetch_data():
    try:
        query = select(AccessLog).order_by(AccessLog.start_local.desc())
        df = pd.read_sql(query, engine)
        if not df.empty:
            df['start_local'] = pd.to_datetime(df['start_local'])
            df['duration_ms'] = df['duration'] / 1_000_000
            df['hour'] = df['start_local'].dt.hour
            df['day_name'] = df['start_local'].dt.day_name()
            df['status_group'] = df['status_code'].apply(lambda x: f"{str(x)[0]}xx")
        return df
    except: return pd.DataFrame()

df_full = fetch_data()

if df_full.empty:
    st.warning("⚠️ No traffic data found. Ensure the worker is running.")
    if st.button("🔄 Refresh"): st.rerun()
else:
    # SIDEBAR
    st.sidebar.title("🌍 Filters")
    time_range = st.sidebar.selectbox("Range", ["1h", "24h", "7d", "30d", "All"], index=1)
    
    now = datetime.now()
    df = df_full.copy()
    if time_range == "1h": df = df[df['start_local'] > (now - timedelta(hours=1))]
    elif time_range == "24h": df = df[df['start_local'] > (now - timedelta(days=1))]
    elif time_range == "7d": df = df[df['start_local'] > (now - timedelta(days=7))]
    elif time_range == "30d": df = df[df['start_local'] > (now - timedelta(days=30))]

    show_bots = st.sidebar.toggle("Include Bots", value=True)
    if not show_bots: df = df[df['is_bot'] == False]

    hosts = st.sidebar.multiselect("Hosts", options=sorted(df['request_host'].unique()), default=df['request_host'].unique())
    if hosts: df = df[df['request_host'].isin(hosts)]

    # TABS
    tabs = st.tabs(["📊 Overview", "📡 Geo & ASN", "🚀 Performance", "🛡️ Security", "🤖 Bots", "🕵️ Investigator", "📺 Live"])

    with tabs[0]:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Requests", f"{len(df):,}")
        c2.metric("Bandwidth", format_bytes(df['content_size'].sum()))
        c3.metric("Avg Latency", f"{df['duration_ms'].mean():.2f} ms")
        c4.metric("Success Rate", f"{(df['status_code'] < 400).mean()*100:.1f}%")

        st.subheader("Traffic Timeline")
        timeline = df.set_index('start_local').groupby([pd.Grouper(freq='1min'), 'status_group']).size().unstack(fill_value=0).reset_index()
        st.plotly_chart(px.area(timeline, x='start_local', y=timeline.columns[1:], template="plotly_dark"), use_container_width=True)

        st.subheader("Service Health (Last 15m)")
        recent = df_full[df_full['start_local'] > (now - timedelta(minutes=15))]
        health_data = []
        for h in df_full['request_host'].unique():
            h_recent = recent[recent['request_host'] == h]
            status = "🟢 Active" if len(h_recent) > 0 else "⚪ Inactive"
            health_data.append({"Host": h, "Status": status, "Req (15m)": len(h_recent)})
        st.table(pd.DataFrame(health_data))

    with tabs[1]:
        col_g1, col_g2 = st.columns(2)
        with col_g1:
            st.subheader("Top Countries")
            country_stats = df['country_code'].value_counts().reset_index()
            st.plotly_chart(px.bar(country_stats, x='count', y='country_code', orientation='h', template="plotly_dark"), use_container_width=True)
        with col_g2:
            st.subheader("Top ASN (Providers)")
            asn_stats = df['asn'].value_counts().head(10).reset_index()
            st.plotly_chart(px.pie(asn_stats, names='asn', values='count', hole=0.4, template="plotly_dark"), use_container_width=True)

    with tabs[2]:
        st.subheader("Slowest Endpoints")
        slowest = df.groupby('request_path')['duration_ms'].agg(['mean', 'count']).sort_values('mean', ascending=False).head(15).reset_index()
        st.plotly_chart(px.bar(slowest, x='mean', y='request_path', orientation='h', labels={'mean':'Avg ms'}, template="plotly_dark"), use_container_width=True)

    with tabs[3]:
        st.subheader("Top Errors (4xx/5xx)")
        errors = df[df['status_code'] >= 400]['request_path'].value_counts().head(15).reset_index()
        st.table(errors)

    with tabs[4]:
        st.subheader("Bot Breakdown")
        bot_fam = df[df['is_bot'] == True]['browser_family'].value_counts().reset_index()
        st.plotly_chart(px.bar(bot_fam, x='count', y='browser_family', orientation='h', template="plotly_dark"), use_container_width=True)

    with tabs[5]:
        st.subheader("IP Investigator")
        ip_in = st.text_input("IP Address...").strip()
        if ip_in:
            res = df_full[df_full['client_addr'] == ip_in]
            if not res.empty:
                st.write(f"**Results for {ip_in} ({res.iloc[0]['country_code']} - {res.iloc[0]['asn']})**")
                st.dataframe(res[['start_local', 'request_method', 'request_host', 'request_path', 'status_code']].head(50), use_container_width=True)
            else: st.warning("No data found.")

    with tabs[6]:
        st.subheader("Live View (Last 50)")
        st.dataframe(df_full[['start_local', 'client_addr', 'country_code', 'request_method', 'request_host', 'request_path', 'status_code']].head(50), use_container_width=True)
        if st.button("Manual Refresh"): st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.caption(f"Sync: {datetime.now().strftime('%H:%M:%S')}")
    if st.sidebar.button("🔄 Refresh Data"): st.rerun()
