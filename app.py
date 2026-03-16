import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from models import engine, AccessLog
from crowdsec import CrowdSecManager
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

# Sidebar: Data Limit
data_limit = st.sidebar.select_slider("Data Scan Depth", options=[1000, 10000, 50000, 100000], value=50000)
df_full = fetch_data(limit=data_limit)

if df_full.empty:
    st.warning("⚠️ No traffic data found. God Mode is waiting for logs...")
    if st.button("🔄 Force Sync"): st.rerun()
else:
    # --- SIDEBAR ---
    st.sidebar.title("🎮 Command Center")
    
    # System Pulse Widget
    with st.sidebar.expander("💓 System Pulse", expanded=True):
        if not df_full.empty:
            last_log = df_full.iloc[0]['start_local']
            diff = (datetime.now() - last_log).total_seconds()
            status_color = "🟢" if diff < 60 else "🟡" if diff < 300 else "🔴"
            st.write(f"{status_color} **Worker:** {'Active' if diff < 300 else 'Stale'}")
            st.caption(f"Last Log: {last_log.strftime('%H:%M:%S')}")
            
            # DB Stats
            try:
                from sqlalchemy import text
                with engine.connect() as conn:
                    db_size = conn.execute(text("SELECT pg_size_pretty(pg_database_size(current_database()))")).scalar()
                    row_count = conn.execute(text("SELECT count(*) FROM access_logs")).scalar()
                st.write(f"💾 **DB Size:** {db_size}")
                st.write(f"📈 **Rows:** {row_count:,}")
            except: pass
        else:
            st.error("🔴 Worker Offline")

    date_mode = st.sidebar.radio("Time Filter", ["Presets", "Custom Range"])
    now = datetime.now()
    df = df_full.copy()
    
    # Selection and Previous Period calculation
    if date_mode == "Presets":
        preset = st.sidebar.selectbox("Range", ["1h", "24h", "7d", "30d", "All Time"], index=1)
        if preset == "1h": 
            df = df[df['start_local'] > (now - timedelta(hours=1))]
            df_prev = df_full[(df_full['start_local'] <= (now - timedelta(hours=1))) & (df_full['start_local'] > (now - timedelta(hours=2)))]
        elif preset == "24h": 
            df = df[df['start_local'] > (now - timedelta(days=1))]
            df_prev = df_full[(df_full['start_local'] <= (now - timedelta(days=1))) & (df_full['start_local'] > (now - timedelta(days=2)))]
        elif preset == "7d": 
            df = df[df['start_local'] > (now - timedelta(days=7))]
            df_prev = df_full[(df_full['start_local'] <= (now - timedelta(days=7))) & (df_full['start_local'] > (now - timedelta(days=14)))]
        elif preset == "30d": 
            df = df[df['start_local'] > (now - timedelta(days=30))]
            df_prev = df_full[(df_full['start_local'] <= (now - timedelta(days=30))) & (df_full['start_local'] > (now - timedelta(days=60)))]
        else:
            df_prev = pd.DataFrame() # No comparison for All Time
    else:
        start_date = st.sidebar.date_input("Start", now - timedelta(days=7))
        end_date = st.sidebar.date_input("End", now)
        df = df[(df['start_local'].dt.date >= start_date) & (df['start_local'].dt.date <= end_date)]
        # For custom range, just use empty comparison for now
        df_prev = pd.DataFrame()

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
tabs = st.tabs(["📊 Dashboard", "🔒 Security", "📈 Performance", "🌐 Traffic", "🔍 Investigate", "🛡️ CrowdSec", "⚙️ System"])

with tabs[0]:
        # Dashboard: Hauptübersicht
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Total Requests", f"{len(df):,}", delta=f"{len(df) - len(df_prev):+}" if not df_prev.empty else None)
        with c2:
            cur_atk = len(df[df['is_attack'] == True])
            prev_atk = len(df_prev[df_prev['is_attack'] == True]) if not df_prev.empty else 0
            delta_atk = f"{cur_atk - prev_atk:+}" if prev_atk > 0 else None
            st.metric("🚨 Security Events", cur_atk, delta=delta_atk)
        with c3:
            st.metric("🌍 Countries", df['country_code'].nunique())
        with c4:
            st.metric("🏎️ Avg Latency", f"{df['duration_ms'].mean():.0f} ms" if not df.empty else "0 ms")
        
        # Globaler Überblick
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            st.subheader("🌐 Global Traffic")
            geo_counts = df.groupby('country_code').size().reset_index(name='Requests')
            geo_counts = geo_counts.merge(df[['country_code', 'country_name']].drop_duplicates(), on='country_code', how='left')
            st.plotly_chart(px.scatter_geo(geo_counts, locations="country_code", hover_name="country_name", size="Requests",
                                         projection="natural earth", template="plotly_dark"), use_container_width=True)
        
        with col_d2:
            st.subheader("📊 Traffic Timeline")
            timeline = df.set_index('start_local').groupby(pd.Grouper(freq='5min')).size().reset_index(name='Requests')
            st.plotly_chart(px.area(timeline, x='start_local', y=timeline.columns[1:], template="plotly_dark", 
                                  color_discrete_sequence=px.colors.qualitative.Safe), use_container_width=True)
        
        # Schnelle Insights
        st.subheader("🚀 Quick Insights")
        col_i1, col_i2 = st.columns(2)
        with col_i1:
            # Top Hosts
            top_hosts = df['request_host'].value_counts().head(5)
            st.write("**Top Hosts**")
            for host, count in top_hosts.items():
                st.write(f"`{host}`: {count:,} requests")
            
            # Error Rate
            error_rate = (len(df[df['status_code'] >= 400]) / len(df) * 100) if len(df) > 0 else 0
            st.write(f"**Error Rate:** {error_rate:.1f}%")
        
        with col_i2:
            # Traffic by Status
            status_groups = df['status_group'].value_counts()
            st.write("**Status Distribution**")
            for status, count in status_groups.head(5).items():
                st.write(f"{status}: {count:,}")
            
            # Bot Traffic
            bot_count = len(df[df['is_bot'] == True])
            bot_pct = (bot_count / len(df) * 100) if len(df) > 0 else 0
            st.write(f"**Bot Traffic:** {bot_count:,} ({bot_pct:.1f}%)")

with tabs[1]:
        # Security Tab
        st.subheader("🔒 Security Dashboard")
        
        # Security Metrics
        col_s1, col_s2, col_s3, col_s4 = st.columns(4)
        with col_s1:
            st.metric("🚨 Attacks", len(df[df['is_attack'] == True]))
        with col_s2:
            st.metric("🌍 Countries", df[df['is_attack'] == True]['country_code'].nunique())
        with col_s3:
            st.metric("🔴 Suspicious IPs", df[df['is_attack'] == True]['client_addr'].nunique())
        with col_s4:
            attack_rate = (len(df[df['is_attack'] == True]) / len(df) * 100) if len(df) > 0 else 0
            st.metric("📊 Attack Rate", f"{attack_rate:.1f}%")
        
        # Security Map
        st.subheader("🌍 Attack Geography")
        attack_df = df[df['is_attack'] == True].groupby(['country_name', 'country_code']).size().reset_index(name='Attacks')
        if not attack_df.empty:
            st.plotly_chart(px.scatter_geo(attack_df, locations="country_code", size="Attacks", hover_name="country_name",
                                          projection="natural earth", template="plotly_dark", color="Attacks",
                                          color_continuous_scale="Reds"), use_container_width=True)
        else: 
            st.info("No geo-locatable attacks found.")
        
        # Security Details
        sec_col1, sec_col2 = st.columns(2)
        with sec_col1:
            st.subheader("🛡️ Security Audit")
            st.write("**Top Attack Paths**")
            attack_paths = df[df['is_attack'] == True]['request_path'].value_counts().head(10)
            if not attack_paths.empty:
                st.table(attack_paths)
            else:
                st.info("No attack paths found")
            
            st.write("**Most Block-worthy IPs**")
            audit_ips = df[df['is_attack'] == True].groupby('client_addr').agg({'id':'count', 'country_code':'first', 'asn':'first'}).sort_values('id', ascending=False)
            if not audit_ips.empty:
                st.dataframe(audit_ips.head(10), use_container_width=True)
            else:
                st.info("No suspicious IPs found")
        
        with sec_col2:
            st.subheader("📋 Security Log")
            atk_only = df[df['is_attack'] == True]
            if not atk_only.empty:
                st.warning(f"Found {len(atk_only)} security events")
                st.dataframe(atk_only[['start_local', 'client_addr', 'country_code', 'request_path', 'request_user_agent', 'asn']].head(15), use_container_width=True)
            else:
                st.success("No malicious activity detected")
            
            st.write("**Suspicious User Agents**")
            sus_agents = df[df['is_attack'] == True]['request_user_agent'].value_counts().head(10)
            if not sus_agents.empty:
                st.table(sus_agents)
            else:
                st.info("No suspicious user agents")

with tabs[2]:
        st.subheader("🌊 Advanced Traffic Flow")
        col_f1, col_f2 = st.columns([1, 3])
        with col_f1:
            st.write("**Flow Controls**")
            sample_size = st.slider("Sample Size", 100, 5000, 1000)
            show_asn = st.checkbox("Include Provider (ASN)", value=True)
            st.caption("Heavier flows may take longer to render.")
        
        with col_f2:
            if not df.empty:
                s_df = df.sample(min(len(df), sample_size))
                
                # Define Layers
                layers = ['country_code', 'request_host', 'status_group']
                if show_asn: layers.insert(1, 'asn')
                
                # Build Sankey data
                nodes = []
                for layer in layers:
                    nodes.extend(s_df[layer].fillna('Unknown').unique())
                nodes = list(dict.fromkeys(nodes))
                node_map = {name: i for i, name in enumerate(nodes)}
                
                links = []
                # Helper for link coloring
                color_map = {
                    '2xx': 'rgba(0, 204, 150, 0.4)',
                    '3xx': 'rgba(25, 211, 243, 0.4)',
                    '4xx': 'rgba(239, 85, 59, 0.4)',
                    '5xx': 'rgba(171, 100, 242, 0.4)'
                }
                
                for i in range(len(layers) - 1):
                    source_layer = layers[i]
                    target_layer = layers[i+1]
                    
                    # Group by layers and include status_group for coloring if it's the last hop
                    group_cols = list(dict.fromkeys([source_layer, target_layer, 'status_group']))
                    grouped = s_df.groupby(group_cols).size().reset_index(name='val')
                    
                    for _, row in grouped.iterrows():
                        links.append(dict(
                            source=node_map[row[source_layer] if pd.notna(row[source_layer]) else 'Unknown'],
                            target=node_map[row[target_layer] if pd.notna(row[target_layer]) else 'Unknown'],
                            value=row['val'],
                            color=color_map.get(row['status_group'], 'rgba(255,255,255,0.1)')
                        ))
                
                fig_sankey = go.Figure(data=[go.Sankey(
                    node = dict(
                        pad = 20, 
                        thickness = 15, 
                        line = dict(color = "black", width = 0.5), 
                        label = nodes, 
                        color = "rgba(0, 204, 150, 0.8)"
                    ),
                    link = dict(
                        source = [l['source'] for l in links], 
                        target = [l['target'] for l in links], 
                        value = [l['value'] for l in links],
                        color = [l['color'] for l in links]
                    )
                )])
                fig_sankey.update_layout(template="plotly_dark", font_size=12, height=600, margin=dict(l=10, r=10, t=10, b=10))
                st.plotly_chart(fig_sankey, use_container_width=True)
            else:
                st.info("No data available for the current filters.")

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
        st.subheader("🛣️ Endpoint Analytics")
        path_stats = df.groupby('request_path').agg({
            'id': 'count',
            'duration_ms': 'mean',
            'status_code': lambda x: (x >= 400).mean() * 100,
            'content_size': 'sum'
        }).rename(columns={
            'id': 'Hits',
            'duration_ms': 'Avg Latency',
            'status_code': 'Error %',
            'content_size': 'Total Size'
        }).sort_values('Hits', ascending=False)
        
        st.write("**Top Endpoints (Detailed)**")
        st.dataframe(path_stats.style.format({
            'Avg Latency': '{:.2f} ms',
            'Error %': '{:.1f}%',
            'Total Size': lambda x: f"{x/(1024**2):.2f} MB"
        }), use_container_width=True)
        
        col_ee1, col_ee2 = st.columns(2)
        with col_ee1:
            st.write("**Slowest Endpoints**")
            st.table(path_stats.sort_values('Avg Latency', ascending=False).head(10)['Avg Latency'])
        with col_ee2:
            st.write("**Most Unstable Endpoints**")
            st.table(path_stats.sort_values('Error %', ascending=False).head(10)['Error %'])

with tabs[7]:
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

with tabs[8]:
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

with tabs[9]:
        st.subheader("🕵️ Advanced IP Investigator")
        ip_in = st.text_input("Deep Audit IP Address...").strip()
        if ip_in:
            res = df_full[df_full['client_addr'] == ip_in]
            if not res.empty:
                st.write(f"**IP Profile: {ip_in} | Country: {res.iloc[0]['country_name']} | Provider: {res.iloc[0]['asn']}**")
                
                cs = CrowdSecManager()
                cs_status = cs.get_ip_reputation(ip_in)
                
                col_inv1, col_inv2, col_inv3 = st.columns(3)
                with col_inv1:
                    st.metric("Total Requests", len(res))
                    st.metric("Attack Events", len(res[res['is_attack'] == True]))
                with col_inv2:
                    # Heuristic Analysis
                    st.markdown("#### 🧠 Heuristic Intent Analysis")
                    unique_paths = res['request_path'].nunique()
                    error_rate = (res['status_code'] >= 400).mean() * 100
                    
                    if res.iloc[0]['is_bot']:
                        st.warning("🤖 **Identity:** Confirmed Bot/Crawler")
                    elif error_rate > 50 and len(res) > 10:
                        st.error("🚨 **Intent:** Likely Scanner/Bruteforcer (High Error Rate)")
                    elif unique_paths > len(res) * 0.8 and len(res) > 5:
                        st.error("🔎 **Intent:** Path Enumerator (High Path Variability)")
                    elif len(res[res['is_attack'] == True]) > 0:
                        st.error("🔥 **Intent:** Confirmed Malicious (Known Exploit Patterns)")
                    else:
                        st.success("✅ **Intent:** Likely Human / Legitimate Traffic")
                
                with col_inv3:
                    st.markdown("#### 🛡️ CrowdSec Status")
                    if cs_status:
                        st.error(f"🚫 **Blocked:** {cs_status.get('type')} (Origin: {cs_status.get('origin')})")
                        st.caption(f"Reason: {cs_status.get('reason')}")
                        st.caption(f"Until: {cs_status.get('until')}")
                        if st.button("🔓 Unblock IP"):
                            if cs.unblock_ip(ip_in):
                                st.success(f"IP {ip_in} unblocked!")
                                st.rerun()
                    else:
                        st.success("✅ **Not Blocked** in CrowdSec LAPI")
                        if st.button("🚫 Manual Block in CrowdSec"):
                            if cs.block_ip(ip_in, reason="Manual Block from Traefik God Mode"):
                                st.success(f"IP {ip_in} blocked successfully!")
                                st.rerun()
                            else:
                                st.error("Failed to block IP. Check CROWDSEC_LAPI_KEY.")

                st.markdown(f"[Search on AbuseIPDB](https://www.abuseipdb.com/check/{ip_in}) | [Whois Lookup](https://who.is/whois-ip/ip-address/{ip_in})")
                st.write("**Historical Requests**")
                st.dataframe(res[['start_local', 'request_method', 'request_host', 'request_path', 'status_code', 'is_attack']].head(100), use_container_width=True)
            else: st.warning("IP not found.")

with tabs[10]:
        st.subheader("📺 God Mode Live Stream")
        st.caption("Latest 200 requests (updates every sync)")
        live_df = df_full[['start_local', 'client_addr', 'country_code', 'request_host', 'request_path', 'status_code', 'is_attack']].head(200)
        st.dataframe(live_df, use_container_width=True)
        
        c_l1, c_l2 = st.columns(2)
        with c_l1:
            if st.button("Manual Pulse"): st.rerun()
        with c_l2:
            st.download_button("Export as CSV", data=df.to_csv(index=False), file_name=f"traefik_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")

with tabs[11]:
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

with tabs[12]:
        st.subheader("🚨 Malicious Activity Log")
        atk_only = df[df['is_attack'] == True]
        if not atk_only.empty:
            st.warning(f"Found {len(atk_only)} security events in the current range.")
            st.dataframe(atk_only[['start_local', 'client_addr', 'country_code', 'request_path', 'request_user_agent', 'asn']], use_container_width=True)
        else:
            st.success("No malicious activity detected in the current range.")

with tabs[13]:
        st.subheader("🛡️ CrowdSec Management Hub")
        cs = CrowdSecManager()
        
        c_cs1, c_cs2 = st.columns([1, 2])
        with c_cs1:
            st.markdown("#### ➕ Manual Decision")
            with st.form("block_form"):
                block_ip = st.text_input("IP Address to Block")
                block_dur = st.selectbox("Duration", ["1h", "24h", "72h", "168h", "720h"], index=1)
                block_reason = st.text_input("Reason", value="Manual Admin Block")
                if st.form_submit_button("🔨 Ban IP"):
                    if block_ip:
                        if cs.block_ip(block_ip, duration=block_dur, reason=block_reason):
                            st.success(f"IP {block_ip} banned.")
                            st.rerun()
                        else: st.error("LAPI Error.")
        
        with c_cs2:
            st.markdown("#### 📜 Active Decisions")
            decisions = cs.get_all_decisions()
            if decisions:
                d_df = pd.DataFrame(decisions)
                st.dataframe(d_df[['value', 'type', 'origin', 'duration', 'reason', 'until']], use_container_width=True)
                
                unblock_val = st.selectbox("Select IP to Unblock", options=[d['value'] for d in decisions])
                if st.button("🔓 Remove Decision"):
                    if cs.unblock_ip(unblock_val):
                        st.success(f"Unblocked {unblock_val}")
                        st.rerun()
            else:
                st.info("No active decisions in CrowdSec.")

with tabs[14]:
        st.subheader("🏥 System Health & Database")
        col_h1, col_h2 = st.columns(2)
        with col_h1:
            st.write("**Database Statistics**")
            try:
                from sqlalchemy import text
                with engine.connect() as conn:
                    db_size = conn.execute(text("SELECT pg_size_pretty(pg_database_size(current_database()))")).scalar()
                    row_count = conn.execute(text("SELECT count(*) FROM access_logs")).scalar()
                    earliest = conn.execute(text("SELECT min(start_local) FROM access_logs")).scalar()
                
                st.info(f"**DB Size:** {db_size} | **Total Rows:** {row_count:,}")
                st.info(f"**Retention Start:** {earliest.strftime('%Y-%m-%d %H:%M:%S') if earliest else 'N/A'}")
            except Exception as e:
                st.error(f"Error fetching DB stats: {e}")
        
        with col_h2:
            st.write("**Maintenance Controls**")
            if st.button("🧹 Force Manual Prune (Keep last 30 days)"):
                try:
                    from sqlalchemy import text
                    cutoff = datetime.now() - timedelta(days=30)
                    with engine.begin() as conn:
                        res = conn.execute(text("DELETE FROM access_logs WHERE start_local < :cutoff"), {"cutoff": cutoff})
                        st.success(f"Pruned {res.rowcount} old records.")
                except Exception as e:
                    st.error(f"Pruning failed: {e}")
            
            if st.button("🔄 Clear App Cache"):
                st.cache_data.clear()
                st.success("Cache cleared successfully.")

st.sidebar.markdown("---")
st.sidebar.caption(f"Last Pulse: {datetime.now().strftime('%H:%M:%S')}")
if st.sidebar.button("⚡ Force Pulse"): st.rerun()
