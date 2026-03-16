import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from models import engine, AccessLog
from sqlalchemy import select, func
from datetime import datetime, timedelta
import io

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Traefik Ultimate Monitor Pro",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# --- THEME STYLING ---
st.markdown("""
<style>
    [data-testid="stMetric"] { border: 1px solid rgba(255, 255, 255, 0.1); padding: 1rem; border-radius: 0.5rem; background: rgba(255, 255, 255, 0.05); }
    .stTabs [data-baseweb="tab-list"] { gap: 10px; }
    .stTabs [data-baseweb="tab"] { border-radius: 6px 6px 0px 0px; padding: 10px 20px; background-color: rgba(255, 255, 255, 0.03); }
    .stTabs [aria-selected="true"] { color: #00CC96; border-bottom: 2px solid #00CC96; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Traefik Ultimate Monitor Pro")

def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

@st.cache_data(ttl=10)
def fetch_data():
    try:
        query = select(AccessLog).order_by(AccessLog.start_local.desc())
        df = pd.read_sql(query, engine)
        if not df.empty:
            df['start_local'] = pd.to_datetime(df['start_local'])
            df['duration_ms'] = df['duration'] / 1_000_000 # ns to ms
            df['hour'] = df['start_local'].dt.hour
            df['day_name'] = df['start_local'].dt.day_name()
            df['status_group'] = df['status_code'].apply(lambda x: f"{str(x)[0]}xx")
        return df
    except Exception:
        return pd.DataFrame()

df_full = fetch_data()

if df_full.empty:
    st.warning("⚠️ No traffic data found. Ensure the worker is running and Traefik is logging.")
    if st.button("🔄 Check Again"):
        st.rerun()
else:
    # --- SIDEBAR ---
    st.sidebar.title("🔍 Advanced Controls")
    time_range = st.sidebar.selectbox("📅 Range", ["1h", "24h", "7d", "30d", "All Time"], index=1)
    
    now = datetime.now()
    df = df_full.copy()
    if time_range == "1h": df = df[df['start_local'] > (now - timedelta(hours=1))]
    elif time_range == "24h": df = df[df['start_local'] > (now - timedelta(days=1))]
    elif time_range == "7d": df = df[df['start_local'] > (now - timedelta(days=7))]
    elif time_range == "30d": df = df[df['start_local'] > (now - timedelta(days=30))]

    hosts = st.sidebar.multiselect("🌍 Hosts", options=sorted(df['request_host'].unique()), default=df['request_host'].unique())
    if hosts: df = df[df['request_host'].isin(hosts)]

    # CSV Export
    csv = df.to_csv(index=False).encode('utf-8')
    st.sidebar.download_button("📥 Export CSV", data=csv, file_name=f"traefik_stats_{datetime.now().strftime('%Y%m%d_%H%M')}.csv", mime='text/csv')

    # --- MAIN TABS ---
    tabs = st.tabs(["📊 Overview", "🚀 Performance", "🛡️ Security", "🤖 Clients & Bots", "🕵️ IP Investigator"])

    with tabs[0]:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Requests", f"{len(df):,}")
        c2.metric("Bandwidth", format_bytes(df['content_size'].sum()))
        c3.metric("P95 Latency", f"{df['duration_ms'].quantile(0.95):.2f} ms")
        success_rate = (df['status_code'] < 400).mean() * 100
        c4.metric("Success Rate", f"{success_rate:.1f}%")

        st.subheader("HTTP Status over Time")
        timeline = df.set_index('start_local').groupby([pd.Grouper(freq='1min'), 'status_group']).size().unstack(fill_value=0).reset_index()
        fig_timeline = px.area(timeline, x='start_local', y=timeline.columns[1:], title="Status Code Volume (1min bins)", template="plotly_dark", color_discrete_sequence=px.colors.qualitative.Pastel)
        st.plotly_chart(fig_timeline, use_container_width=True)

        st.subheader("Traffic Heatmap (Density)")
        heat_data = df.groupby(['day_name', 'hour']).size().reset_index(name='count')
        days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        heat_pivot = heat_data.pivot(index='day_name', columns='hour', values='count').reindex(days_order)
        fig_heat = px.imshow(heat_pivot, color_continuous_scale='Viridis', template="plotly_dark")
        st.plotly_chart(fig_heat, use_container_width=True)

    with tabs[1]:
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            st.subheader("Slowest Endpoints (Avg)")
            slowest = df.groupby('request_path')['duration_ms'].agg(['mean', 'count']).sort_values('mean', ascending=False).head(15).reset_index()
            fig_slow = px.bar(slowest, x='mean', y='request_path', labels={'mean':'Avg Latency (ms)'}, orientation='h', template="plotly_dark")
            st.plotly_chart(fig_slow, use_container_width=True)
        with col_p2:
            st.subheader("Bandwidth per Host")
            bw_host = df.groupby('request_host')['content_size'].sum().sort_values(ascending=False).reset_index()
            bw_host['formatted'] = bw_host['content_size'].apply(format_bytes)
            fig_bw = px.bar(bw_host, x='content_size', y='request_host', labels={'content_size':'Bytes'}, orientation='h', template="plotly_dark")
            st.plotly_chart(fig_bw, use_container_width=True)

    with tabs[2]:
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.subheader("Critical Errors (5xx)")
            err_5xx = df[df['status_code'] >= 500]['request_path'].value_counts().head(10).reset_index()
            if not err_5xx.empty: st.table(err_5xx)
            else: st.success("No 500 errors detected!")
        with col_s2:
            st.subheader("Client Errors (4xx)")
            err_4xx = df[(df['status_code'] >= 400) & (df['status_code'] < 500)]['request_path'].value_counts().head(10).reset_index()
            st.table(err_4xx)

    with tabs[3]:
        c_bot1, c_bot2, c_bot3 = st.columns(3)
        with c_bot1:
            bot_data = df['is_bot'].map({True: '🤖 Bot', False: '👤 Human'}).value_counts().reset_index()
            st.plotly_chart(px.pie(bot_data, names='is_bot', values='count', hole=0.4, title="Bot vs Human", template="plotly_dark"), use_container_width=True)
        with c_bot2:
            os_data = df['os_family'].value_counts().head(5).reset_index()
            st.plotly_chart(px.pie(os_data, names='os_family', values='count', title="Top OS", template="plotly_dark"), use_container_width=True)
        with c_bot3:
            device_data = df['device_family'].value_counts().head(5).reset_index()
            st.plotly_chart(px.pie(device_data, names='device_family', values='count', title="Top Device", template="plotly_dark"), use_container_width=True)

    with tabs[4]:
        st.subheader("🔎 IP Investigation")
        ip_query = st.text_input("IP Address...").strip()
        if ip_query:
            ip_res = df_full[df_full['client_addr'] == ip_query]
            if not ip_res.empty:
                i_c1, i_c2, i_c3 = st.columns(3)
                i_c1.metric("Total Hits", len(ip_res))
                i_c2.metric("Success Rate", f"{(ip_res['status_code'] < 400).mean()*100:.1f}%")
                i_c3.metric("Last Seen", ip_res['start_local'].max().strftime('%Y-%m-%d %H:%M'))
                st.write("**Top Domains**")
                st.bar_chart(ip_res['request_host'].value_counts().head(10))
                st.write("**Recent Requests**")
                st.dataframe(ip_res[['start_local', 'request_method', 'request_host', 'request_path', 'status_code']].head(50), use_container_width=True)
            else: st.warning("IP not found in logs.")

    st.sidebar.markdown("---")
    st.sidebar.caption(f"Sync: {datetime.now().strftime('%H:%M:%S')}")
    if st.sidebar.button("🔄 Refresh"): st.rerun()
