import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from models import engine, AccessLog
from sqlalchemy import select
from datetime import datetime, timedelta

st.set_page_config(page_title="Traefik God Mode Monitor", layout="wide", page_icon="⚡")

# Custom CSS for God Mode
st.markdown("""
<style>
    [data-testid="stMetric"] { border: 1px solid rgba(0, 204, 150, 0.3); padding: 1rem; border-radius: 0.5rem; background: rgba(0, 204, 150, 0.05); }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] { border-radius: 4px 4px 0px 0px; padding: 8px 12px; background-color: rgba(255, 255, 255, 0.03); font-size: 14px; }
    .stTabs [aria-selected="true"] { color: #00CC96; border-bottom: 2px solid #00CC96; font-weight: bold; }
    .insight-card { padding: 15px; border-radius: 10px; border-left: 5px solid #00CC96; background: rgba(255,255,255,0.02); margin-bottom: 10px; }
</style>
""", unsafe_allow_html=True)

st.title("⚡ Traefik God Mode Monitor")

@st.cache_data(ttl=5)
def fetch_data():
    try:
        query = select(AccessLog).order_by(AccessLog.start_local.desc())
        df = pd.read_sql(query, engine)
        if not df.empty:
            df['start_local'] = pd.to_datetime(df['start_local'])
            df['duration_ms'] = df['duration'] / 1_000_000
            df['status_group'] = df['status_code'].apply(lambda x: f"{str(x)[0]}xx")
        return df
    except: return pd.DataFrame()

df_full = fetch_data()

if df_full.empty:
    st.warning("⚠️ No traffic data found. God Mode is waiting for logs...")
    if st.button("🔄 Force Sync"): st.rerun()
else:
    # --- SIDEBAR ---
    st.sidebar.title("🎮 Command Center")
    date_mode = st.sidebar.radio("Time Filter", ["Presets", "Custom Range"])
    now = datetime.now()
    df = df_full.copy()
    
    if date_mode == "Presets":
        preset = st.sidebar.selectbox("Range", ["1h", "24h", "7d", "30d", "All Time"], index=1)
        if preset == "1h": df = df[df['start_local'] > (now - timedelta(hours=1))]
        elif preset == "24h": df = df[df['start_local'] > (now - timedelta(days=1))]
        elif preset == "7d": df = df[df['start_local'] > (now - timedelta(days=7))]
        elif preset == "30d": df = df[df['start_local'] > (now - timedelta(days=30))]
    else:
        start_date = st.sidebar.date_input("Start", now - timedelta(days=7))
        end_date = st.sidebar.date_input("End", now)
        df = df[(df['start_local'].dt.date >= start_date) & (df['start_local'].dt.date <= end_date)]

    hosts = st.sidebar.multiselect("Active Hosts", options=sorted(df['request_host'].unique()), default=df['request_host'].unique())
    if hosts: df = df[df['request_host'].isin(hosts)]

    status_groups = st.sidebar.multiselect("Status Groups", options=sorted(df['status_group'].unique()), default=df['status_group'].unique())
    if status_groups: df = df[df['status_group'].isin(status_groups)]

    methods = st.sidebar.multiselect("Methods", options=sorted(df['request_method'].unique()), default=df['request_method'].unique())
    if methods: df = df[df['request_method'].isin(methods)]

    if st.sidebar.checkbox("Hide Attack Traffic"):
        df = df[df['is_attack'] == False]
    if st.sidebar.checkbox("Show Attacks Only"):
        df = df[df['is_attack'] == True]

    # --- TABS ---
    tabs = st.tabs(["📊 Dashboard", "🧠 God Insights", "🌊 Traffic Flow", "🗺️ Security Map", "🛡️ Audit", "🚀 Performance", "🌐 Sources", "🤖 Clients", "🕵️ Investigator", "📺 Live Stream", "🧪 Error Lab"])

    with tabs[0]:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Hits", f"{len(df):,}")
        c2.metric("Attack Volume", f"{len(df[df['is_attack'] == True]):,}", delta=f"{(len(df[df['is_attack']==True])/len(df)*100):.1f}% of traffic", delta_color="inverse")
        c3.metric("Unique IPs", f"{df['client_addr'].nunique():,}")
        c4.metric("Bandwidth", f"{df['content_size'].sum()/(1024**2):.2f} MB")

        st.subheader("Real-time Pulse")
        timeline = df.set_index('start_local').groupby([pd.Grouper(freq='1min'), 'status_group']).size().unstack(fill_value=0).reset_index()
        st.plotly_chart(px.area(timeline, x='start_local', y=timeline.columns[1:], template="plotly_dark", color_discrete_sequence=px.colors.qualitative.Safe), use_container_width=True)
        
        st.subheader("⚡ Traffic Heatmap (Hourly/Daily)")
        heatmap_df = df.copy()
        heatmap_df['hour'] = heatmap_df['start_local'].dt.hour
        heatmap_df['day'] = heatmap_df['start_local'].dt.strftime('%A')
        heatmap_data = heatmap_df.groupby(['day', 'hour']).size().unstack(fill_value=0)
        days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        heatmap_data = heatmap_data.reindex(days_order).fillna(0)
        st.plotly_chart(px.imshow(heatmap_data, labels=dict(x="Hour of Day", y="Day of Week", color="Requests"), template="plotly_dark", color_continuous_scale="Viridis"), use_container_width=True)

        col_d1, col_d2 = st.columns(2)
        with col_d1:
            st.write("**Top Countries**")
            top_countries = df['country_name'].value_counts().head(10).reset_index()
            st.plotly_chart(px.pie(top_countries, values='count', names='country_name', template="plotly_dark", hole=0.4), use_container_width=True)
        with col_d2:
            st.write("**Status Code Distribution**")
            status_counts = df['status_code'].value_counts().reset_index()
            st.plotly_chart(px.bar(status_counts, x='status_code', y='count', template="plotly_dark", color='status_code'), use_container_width=True)

    with tabs[1]:
        st.subheader("🧠 Smart Anomaly Detection")
        col_i1, col_i2 = st.columns(2)
        
        with col_i1:
            # Insight: Path Scanners
            scanners = df[df['status_code'] == 404].groupby('client_addr').size().sort_values(ascending=False).head(5)
            if not scanners.empty:
                st.markdown(f'<div class="insight-card"><b>🚨 Path Scanning Detected</b><br>IP <code>{scanners.index[0]}</code> has requested {scanners.values[0]} non-existent paths. Likely a bot/scanner.</div>', unsafe_allow_html=True)
            
            # Insight: Bandwidth Hog
            hogs = df.groupby('request_host')['content_size'].sum().sort_values(ascending=False).head(1)
            st.markdown(f'<div class="insight-card"><b>💎 Resource Leader</b><br>Host <code>{hogs.index[0]}</code> is responsible for most traffic ({hogs.values[0]/(1024**2):.1f} MB).</div>', unsafe_allow_html=True)

        with col_i2:
            # Insight: Error Spikes
            recent_err = len(df[(df['start_local'] > (now - timedelta(minutes=30))) & (df['status_code'] >= 400)])
            prev_err = len(df[(df['start_local'] > (now - timedelta(minutes=60))) & (df['start_local'] < (now - timedelta(minutes=30))) & (df['status_code'] >= 400)])
            if recent_err > prev_err * 1.5 and recent_err > 10:
                st.markdown(f'<div class="insight-card" style="border-left-color: #EF553B"><b>🔥 Error Spike</b><br>Errors increased by {((recent_err/max(1,prev_err))-1)*100:.0f}% in the last 30 minutes!</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="insight-card"><b>✅ System Stable</b><br>No significant error spikes or anomalies detected in the current range.</div>', unsafe_allow_html=True)

    with tabs[2]:
        st.subheader("🌊 Traffic Flow (Sankey)")
        if not df.empty:
            s_df = df.sample(min(len(df), 2000))
            all_nodes = list(s_df['country_code'].fillna('Unknown').unique()) + list(s_df['request_host'].unique()) + list(s_df['status_group'].unique())
            node_map = {name: i for i, name in enumerate(all_nodes)}
            
            links = []
            c_h = s_df.groupby(['country_code', 'request_host']).size().reset_index(name='val')
            for _, row in c_h.iterrows():
                links.append(dict(source=node_map[row['country_code'] if pd.notna(row['country_code']) else 'Unknown'], target=node_map[row['request_host']], value=row['val']))
            h_s = s_df.groupby(['request_host', 'status_group']).size().reset_index(name='val')
            for _, row in h_s.iterrows():
                links.append(dict(source=node_map[row['request_host']], target=node_map[row['status_group']], value=row['val']))
                
            fig_sankey = go.Figure(data=[go.Sankey(
                node = dict(pad = 15, thickness = 20, line = dict(color = "black", width = 0.5), label = all_nodes, color = "rgba(0, 204, 150, 0.8)"),
                link = dict(source = [l['source'] for l in links], target = [l['target'] for l in links], value = [l['value'] for l in links], color="rgba(255,255,255,0.1)")
            )])
            fig_sankey.update_layout(title_text="Global Traffic Flow", template="plotly_dark", font_size=10)
            st.plotly_chart(fig_sankey, use_container_width=True)

    with tabs[3]:
        st.subheader("🌍 Security Map (Attacks Only)")
        attack_df = df[df['is_attack'] == True].groupby(['country_name', 'country_code']).size().reset_index(name='Attacks')
        if not attack_df.empty:
            st.plotly_chart(px.scatter_geo(attack_df, locations="country_code", size="Attacks", hover_name="country_name",
                                         projection="natural earth", template="plotly_dark", color="Attacks",
                                         color_continuous_scale="Reds"), use_container_width=True)
        else: st.success("No geo-locatable attacks found.")

    with tabs[4]:
        st.subheader("🛡️ Detailed Security Audit")
        c_a1, c_a2 = st.columns(2)
        with c_a1:
            st.write("**Top Attack Paths**")
            st.table(df[df['is_attack'] == True]['request_path'].value_counts().head(15))
            st.write("**Top 404 Not Found Paths**")
            st.table(df[df['status_code'] == 404]['request_path'].value_counts().head(15))
        with c_a2:
            st.write("**Most Block-worthy IPs**")
            audit_ips = df[df['is_attack'] == True].groupby('client_addr').agg({'id':'count', 'country_code':'first', 'asn':'first'}).sort_values('id', ascending=False)
            st.dataframe(audit_ips, use_container_width=True)
            st.write("**Suspicious User Agents**")
            st.table(df[df['is_attack'] == True]['request_user_agent'].value_counts().head(10))

    with tabs[5]:
        st.subheader("🚀 Performance Metrics")
        st.write("**Average Latency per Host (ms)**")
        st.plotly_chart(px.bar(df.groupby('request_host')['duration_ms'].mean().reset_index(), x='duration_ms', y='request_host', orientation='h', template="plotly_dark"), use_container_width=True)
        
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            st.write("**P95 Latency by Host**")
            p95 = df.groupby('request_host')['duration_ms'].quantile(0.95).reset_index(name='p95_ms')
            st.table(p95)
        with col_p2:
            st.write("**Response Size Distribution**")
            st.plotly_chart(px.histogram(df, x='content_size', nbins=50, template="plotly_dark"), use_container_width=True)

    with tabs[6]:
        st.subheader("🌐 Source & Referer Analysis")
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.write("**Top Referers**")
            referers = df['request_referer'].value_counts().head(15).reset_index()
            st.table(referers)
        with col_s2:
            st.write("**Top Providers (ASN)**")
            asns = df['asn'].value_counts().head(10).reset_index()
            st.plotly_chart(px.pie(asns, values='count', names='asn', template="plotly_dark"), use_container_width=True)
            
        st.write("**Top Entry Points**")
        entry_points = df['entry_point'].value_counts().reset_index()
        st.plotly_chart(px.bar(entry_points, x='entry_point', y='count', template="plotly_dark"), use_container_width=True)

    with tabs[7]:
        st.subheader("🤖 Client & Browser Analysis")
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.write("**Browsers**")
            st.plotly_chart(px.pie(df, names='browser_family', template="plotly_dark"), use_container_width=True)
        with col_c2:
            st.write("**Operating Systems**")
            st.plotly_chart(px.pie(df, names='os_family', template="plotly_dark"), use_container_width=True)
        
        st.write("**Device Types**")
        st.plotly_chart(px.bar(df['device_family'].value_counts().head(10), template="plotly_dark"), use_container_width=True)

        st.write("**Top Detected Bots**")
        bot_df = df[df['is_bot'] == True]
        if not bot_df.empty:
            bot_counts = bot_df['browser_family'].value_counts().head(10).reset_index()
            st.plotly_chart(px.bar(bot_counts, x='count', y='browser_family', orientation='h', template="plotly_dark", color='count'), use_container_width=True)
        else:
            st.info("No significant bot activity detected in this range.")

    with tabs[8]:
        st.subheader("🕵️ Advanced IP Investigator")
        ip_in = st.text_input("Deep Audit IP Address...").strip()
        if ip_in:
            res = df_full[df_full['client_addr'] == ip_in]
            if not res.empty:
                st.write(f"**IP Profile: {ip_in} | Country: {res.iloc[0]['country_name']} | Provider: {res.iloc[0]['asn']}**")
                st.metric("Attack Count", len(res[res['is_attack'] == True]))
                st.markdown(f"[Search on AbuseIPDB](https://www.abuseipdb.com/check/{ip_in}) | [Whois Lookup](https://who.is/whois-ip/ip-address/{ip_in})")
                st.write("**Historical Requests**")
                st.dataframe(res[['start_local', 'request_method', 'request_host', 'request_path', 'status_code', 'is_attack']].head(100), use_container_width=True)
            else: st.warning("IP not found.")

    with tabs[9]:
        st.subheader("📺 God Mode Live Stream")
        st.caption("Latest 200 requests (updates every sync)")
        live_df = df_full[['start_local', 'client_addr', 'country_code', 'request_host', 'request_path', 'status_code', 'is_attack']].head(200)
        st.dataframe(live_df, use_container_width=True)
        
        c_l1, c_l2 = st.columns(2)
        with c_l1:
            if st.button("Manual Pulse"): st.rerun()
        with c_l2:
            st.download_button("Export as CSV", data=df.to_csv(index=False), file_name=f"traefik_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")

    with tabs[10]:
        st.subheader("🧪 Error & 404 Lab")
        err_df = df[df['status_code'] >= 400]
        if not err_df.empty:
            c_e1, c_e2 = st.columns(2)
            with c_e1:
                st.write("**Errors by Host**")
                st.plotly_chart(px.bar(err_df.groupby('request_host').size().reset_index(name='count'), x='count', y='request_host', orientation='h', template="plotly_dark"), use_container_width=True)
            with c_e2:
                st.write("**Errors by Path**")
                st.table(err_df['request_path'].value_counts().head(15))
            
            st.write("**Error Timeline (5-min buckets)**")
            err_timeline = err_df.set_index('start_local').groupby([pd.Grouper(freq='5min'), 'status_code']).size().unstack(fill_value=0).reset_index()
            st.plotly_chart(px.line(err_timeline, x='start_local', y=err_timeline.columns[1:], template="plotly_dark"), use_container_width=True)
        else:
            st.success("Clean sheets! No errors in the current selection.")

    st.sidebar.markdown("---")
    st.sidebar.caption(f"Last Pulse: {datetime.now().strftime('%H:%M:%S')}")
    if st.sidebar.button("⚡ Force Pulse"): st.rerun()
