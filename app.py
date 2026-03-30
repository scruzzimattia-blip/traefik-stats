import streamlit as st
import pandas as pd
import os
import plotly.express as px
import plotly.graph_objects as go
import logging
import ipaddress
from models import engine, AccessLog, SessionLocal
from crowdsec import CrowdSecManager
from sqlalchemy import select, func
from datetime import datetime, timedelta
from cache_service import CacheService, invalidate_cache

@st.cache_data(ttl=120, show_spinner=False)
def transform_df(_df):
    if _df.empty:
        return _df
    df = _df.copy()
    if 'start_local' in df.columns and df['start_local'].dtype == 'object':
        df['start_local'] = pd.to_datetime(df['start_local'])
    if 'duration' in df.columns:
        df['duration_ms'] = df['duration'] / 1_000_000
    if 'status_code' in df.columns:
        df['status_group'] = df['status_code'].astype(str).str[0] + 'xx'
    return df

@st.cache_data(ttl=180, show_spinner=False)
def compute_geo_stats(df):
    if df.empty:
        return pd.DataFrame()
    return df.groupby('country_code').size().reset_index(name='Requests')

@st.cache_data(ttl=180, show_spinner=False)
def compute_top_hosts(df, n=5):
    if df.empty:
        return pd.Series(dtype=int)
    return df['request_host'].value_counts().head(n)

@st.cache_data(ttl=180, show_spinner=False)
def compute_status_dist(df):
    if df.empty:
        return pd.Series(dtype=int)
    return df['status_group'].value_counts()

@st.cache_data(ttl=180, show_spinner=False)
def compute_timeline(df):
    if df.empty:
        return pd.DataFrame()
    return df.set_index('start_local').groupby(pd.Grouper(freq='5min')).size().reset_index(name='Requests')
from data_service import (
    fetch_data, get_abuse_reputation, get_total_logs_count, fetch_logs_paginated, format_bytes,
    get_login_attempts, get_top_slowest_endpoints, get_error_trends, get_bandwidth_spikes,
    get_threat_leaders, get_blocked_countries, add_blocked_country, remove_blocked_country,
    get_worker_stats, update_precomputed_stats, get_session
)
from streamlit_autorefresh import st_autorefresh

logger = logging.getLogger(__name__)

st.set_page_config(page_title="Traefik God Mode Monitor", layout="wide", page_icon="⚡")

st.markdown("""
<style>
    .stAppLoading { opacity: 0.5; }
</style>
""", unsafe_allow_html=True)

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

# Sidebar: Data Limit
data_limit = st.sidebar.select_slider("Data Scan Depth", options=[1000, 10000, 50000, 100000], value=50000)
df_full = fetch_data(limit=data_limit)

# Final safety check: ensure df_full is a DataFrame and not a string/other type from cache
if not hasattr(df_full, 'empty') or isinstance(df_full, (str, dict, list)):
    st.warning("⚠️ Cache corruption or stale data format detected. Cleaning up...")
    invalidate_cache()
    st.rerun()

# Validate DataFrame has required columns
if hasattr(df_full, 'empty') and not df_full.empty:
    required_cols = ['start_local', 'client_addr', 'request_host', 'status_code']
    if not all(col in df_full.columns for col in required_cols):
        st.warning("⚠️ Cache missing required columns. Cleaning up...")
        invalidate_cache()
        st.rerun()

if df_full.empty:
    st.warning("⚠️ No traffic data found. God Mode is waiting for logs...")
    if st.button("🔄 Force Sync"): st.rerun()
else:
    # Ensure start_local is datetime (sometimes JSON serialization in cache makes it string)
    if not df_full.empty and isinstance(df_full.iloc[0]['start_local'], str):
        df_full['start_local'] = pd.to_datetime(df_full['start_local'])
    
    # --- SIDEBAR ---
    st.sidebar.title("🎮 Command Center")
    
    # Auto-Refresh
    refresh_col1, refresh_col2 = st.sidebar.columns([1, 2])
    with refresh_col1:
        st.write("🔄 **Reload**")
    with refresh_col2:
        refresh_interval = st.selectbox("Interval", ["Off", "30s", "1m", "5m"], index=0, label_visibility="collapsed")
        
    if refresh_interval == "30s":
        st_autorefresh(interval=30 * 1000, key="data_refresh")
    elif refresh_interval == "1m":
        st_autorefresh(interval=60 * 1000, key="data_refresh")
    elif refresh_interval == "5m":
        st_autorefresh(interval=300 * 1000, key="data_refresh")
    
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
            except Exception as e:
                logger.debug(f"Database info query failed: {e}")
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

    unique_hosts = sorted(df['request_host'].dropna().unique())
    hosts = st.sidebar.multiselect("Active Hosts", options=unique_hosts, default=unique_hosts)
    if hosts: df = df[df['request_host'].isin(hosts)]

    unique_status = sorted(df['status_group'].dropna().unique())
    status_groups = st.sidebar.multiselect("Status Groups", options=unique_status, default=unique_status)
    if status_groups: df = df[df['status_group'].isin(status_groups)]

    unique_methods = sorted(df['request_method'].dropna().unique())
    methods = st.sidebar.multiselect("Methods", options=unique_methods, default=unique_methods)
    if methods: df = df[df['request_method'].isin(methods)]

    if st.sidebar.checkbox("Hide Attack Traffic"):
        df = df[df['is_attack'] == False]
    if st.sidebar.checkbox("Show Attacks Only"):
        df = df[df['is_attack'] == True]

    # --- TABS ---
    tabs = st.tabs([
        "📊 Dashboard", 
        "🔒 Security", 
        "🌊 Traffic", 
        "🕵️ Investigator", 
        "📺 Live Stream", 
        "🏥 System"
    ])

    with tabs[0]:
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("Total Requests", f"{len(df):,}", delta=f"{len(df) - len(df_prev):+}" if not df_prev.empty else None)
            with c2:
                cur_atk = len(df[df['is_attack'] == True])
                prev_atk = len(df_prev[df_prev['is_attack'] == True]) if not df_prev.empty else 0
                delta_atk = f"{cur_atk - prev_atk:+}" if prev_atk > 0 else None
                st.metric("🚨 Attacks", cur_atk, delta=delta_atk)
            with c3:
                st.metric("🌍 Countries", df['country_code'].nunique())
            with c4:
                st.metric("🏎️ Avg Latency", f"{df['duration_ms'].mean():.0f} ms" if not df.empty else "0 ms")
            
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.subheader("🌐 Traffic by Country")
                geo_counts = df.groupby('country_code').size().reset_index(name='Requests')
                geo_counts = geo_counts.merge(df[['country_code', 'country_name']].drop_duplicates(), on='country_code', how='left')
                st.plotly_chart(px.scatter_geo(geo_counts, locations="country_code", hover_name="country_name", size="Requests",
                                              projection="natural earth", template="plotly_dark"), use_container_width=True)
            
            with col_d2:
                st.subheader("📈 Traffic Timeline")
                timeline = df.set_index('start_local').groupby(pd.Grouper(freq='5min')).size().reset_index(name='Requests')
                st.plotly_chart(px.area(timeline, x='start_local', y=timeline.columns[1:], template="plotly_dark"), use_container_width=True)
            
            col_i1, col_i2 = st.columns(2)
            with col_i1:
                st.write("**Top Hosts**")
                for host, count in df['request_host'].value_counts().head(5).items():
                    st.write(f"`{host}`: {count:,}")
                error_rate = (len(df[df['status_code'] >= 400]) / len(df) * 100) if len(df) > 0 else 0
                st.write(f"**Error Rate:** {error_rate:.1f}%")
            with col_i2:
                st.write("**Status Distribution**")
                for status, count in df['status_group'].value_counts().head(5).items():
                    st.write(f"{status}: {count:,}")
                bot_count = len(df[df['is_bot'] == True])
                bot_pct = (bot_count / len(df) * 100) if len(df) > 0 else 0
                st.write(f"**Bot Traffic:** {bot_count:,} ({bot_pct:.1f}%)")
    
    with tabs[1]:
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
            
            sec_col1, sec_col2 = st.columns(2)
            with sec_col1:
                st.subheader("🌍 Attack Geography")
                attack_df = df[df['is_attack'] == True].groupby(['country_name', 'country_code']).size().reset_index(name='Attacks')
                if not attack_df.empty:
                    st.plotly_chart(px.scatter_geo(attack_df, locations="country_code", size="Attacks", hover_name="country_name",
                                                  projection="natural earth", template="plotly_dark", color="Attacks",
                                                  color_continuous_scale="Reds"), use_container_width=True)
                
                st.write("**Top Attack Paths**")
                st.table(df[df['is_attack'] == True]['request_path'].value_counts().head(10))
                
                st.write("**Most Block-worthy IPs**")
                audit_ips = df[df['is_attack'] == True].groupby('client_addr').agg({'id':'count', 'country_code':'first', 'asn':'first'}).sort_values('id', ascending=False)
                st.dataframe(audit_ips.head(10), use_container_width=True)
            
            with sec_col2:
                st.subheader("🚨 Attack Log")
                total_attacks = get_total_logs_count(filter_attack=True)
                page_size = 15
                total_pages = (total_attacks // page_size) + (1 if total_attacks % page_size > 0 else 0)
                
                if total_attacks > 0:
                    c1, c2 = st.columns([1, 3])
                    with c1:
                        page_num = st.number_input("Page", min_value=1, max_value=max(1, total_pages), value=1)
                    with c2:
                        st.write(f"Page {page_num} of {total_pages} ({total_attacks} total)")
                    
                    offset = (page_num - 1) * page_size
                    atk_page_df = fetch_logs_paginated(limit=page_size, offset=offset, filter_attack=True)
                    st.dataframe(atk_page_df[['start_local', 'client_addr', 'country_code', 'request_path', 'request_user_agent', 'asn']], use_container_width=True)
                else:
                    st.success("No attacks detected")
                
                st.write("**Suspicious User Agents**")
                st.table(df[df['is_attack'] == True]['request_user_agent'].value_counts().head(10))
            
            st.subheader("🛡️ CrowdSec Management")
            cs = CrowdSecManager()
            col_cs1, col_cs2 = st.columns([1, 2])
            with col_cs1:
                with st.form("block_form"):
                    st.write("**Manual Ban**")
                    block_ip = st.text_input("IP Address")
                    block_dur = st.selectbox("Duration", ["1h", "24h", "72h", "168h", "720h"], index=1)
                    block_reason = st.text_input("Reason", value="Manual Block")
                    if st.form_submit_button("🔨 Ban"):
                        valid_ip = False
                        try:
                            ipaddress.ip_address(block_ip)
                            valid_ip = True
                        except ValueError:
                            st.error("Invalid IP address")
                        
                        if valid_ip and block_ip and cs.block_ip(block_ip, duration=block_dur, reason=block_reason):
                            st.success(f"IP {block_ip} banned!")
                            st.rerun()
            
            with col_cs2:
                decisions = cs.get_all_decisions()
                decisions = [d for d in decisions if d.get('origin') != 'CAPI']
                if decisions:
                    d_df = pd.DataFrame(decisions)
                    cols = ['value', 'type', 'origin', 'duration', 'scenario', 'until']
                    d_df = d_df.reindex(columns=cols)
                    st.dataframe(d_df, use_container_width=True)
                    unblock_val = st.selectbox("Unblock IP", options=[d['value'] for d in decisions])
                    if st.button("🔓 Unblock"):
                        if cs.unblock_ip(unblock_val):
                            st.success(f"Unblocked {unblock_val}")
                            st.rerun()
                else:
                    st.info("No active bans")
    
    with tabs[2]:
            st.subheader("🌊 Traffic Flow")
            col_f1, col_f2 = st.columns([1, 3])
            with col_f1:
                sample_size = st.slider("Sample Size", 100, 5000, 1000)
                show_asn = st.checkbox("Include ASN", value=True)
            
            with col_f2:
                if not df.empty:
                    s_df = df.sample(min(len(df), sample_size))
                    layers = ['country_code', 'request_host', 'status_group']
                    if show_asn: layers.insert(1, 'asn')
                    
                    nodes = []
                    for layer in layers:
                        nodes.extend(s_df[layer].fillna('Unknown').unique())
                    nodes = list(dict.fromkeys(nodes))
                    node_map = {name: i for i, name in enumerate(nodes)}
                    
                    links = []
                    color_map = {'2xx': 'rgba(0, 204, 150, 0.4)', '3xx': 'rgba(25, 211, 243, 0.4)', '4xx': 'rgba(239, 85, 59, 0.4)', '5xx': 'rgba(171, 100, 242, 0.4)'}
                    
                    for i in range(len(layers) - 1):
                        group_cols = list(dict.fromkeys([layers[i], layers[i+1], 'status_group']))
                        grouped = s_df.groupby(group_cols).size().reset_index(name='val')
                        for _, row in grouped.iterrows():
                            links.append(dict(
                                source=node_map.get(row[layers[i]] if pd.notna(row.get(layers[i])) else 'Unknown'),
                                target=node_map.get(row[layers[i+1]] if pd.notna(row.get(layers[i+1])) else 'Unknown'),
                                value=row['val'],
                                color=color_map.get(row['status_group'], 'rgba(255,255,255,0.1)')
                            ))
                    
                    fig_sankey = go.Figure(data=[go.Sankey(
                        node=dict(pad=20, thickness=15, line=dict(color="black", width=0.5), label=nodes, color="rgba(0, 204, 150, 0.8)"),
                        link=dict(source=[l['source'] for l in links], target=[l['target'] for l in links], value=[l['value'] for l in links], color=[l['color'] for l in links])
                    )])
                    fig_sankey.update_layout(template="plotly_dark", font_size=12, height=500, margin=dict(l=10, r=10, t=10, b=10))
                    st.plotly_chart(fig_sankey, use_container_width=True)
        
            col_t1, col_t2 = st.columns(2)
            with col_t1:
                st.subheader("🛣️ Top Endpoints")
                path_stats = df.groupby('request_path').agg({'id': 'count', 'duration_ms': 'mean', 'status_code': lambda x: (x >= 400).mean() * 100}).rename(columns={'id': 'Hits', 'duration_ms': 'Avg Latency', 'status_code': 'Error %'}).sort_values('Hits', ascending=False).head(15)
                st.dataframe(path_stats.style.format({'Avg Latency': '{:.2f} ms', 'Error %': '{:.1f}%'}), use_container_width=True)
                
                st.subheader("🐌 Slowest Endpoints")
                slow_df = get_top_slowest_endpoints(10)
                if not slow_df.empty:
                    st.table(slow_df.rename(columns={'request_path': 'Path', 'avg_ms': 'Avg ms', 'hits': 'Hits'}))
                
                st.subheader("🌐 Top Referers")
                st.table(df['request_referer'].value_counts().head(10))
            
            with col_t2:
                st.subheader("📈 Bandwidth")
                bw_c1, bw_c2, bw_c3 = st.columns(3)
                with bw_c1: st.metric("Total", format_bytes(df['content_size'].sum()))
                with bw_c2: st.metric("Avg", format_bytes(df['content_size'].mean()))
                with bw_c3: st.metric("Peak", format_bytes(df['content_size'].max()))
                
                bw_timeline = df.set_index('start_local').groupby(pd.Grouper(freq='5min'))['content_size'].sum().reset_index()
                st.plotly_chart(px.area(bw_timeline, x='start_local', y='content_size', template="plotly_dark", title="Throughput over Time"), use_container_width=True)
                
                st.subheader("📊 Error Trends (24h)")
                error_trends = get_error_trends(24)
                if not error_trends.empty:
                    st.plotly_chart(px.line(error_trends, x='hour', y='count', color='status_code', template="plotly_dark"), use_container_width=True)
                
                st.subheader("🤖 Browsers & Devices")
                col_b1, col_b2 = st.columns(2)
                with col_b1: st.plotly_chart(px.pie(df, names='browser_family', template="plotly_dark"), use_container_width=True)
                with col_b2: st.plotly_chart(px.bar(df['device_family'].value_counts().head(8), template="plotly_dark"), use_container_width=True)
    
    with tabs[3]:
            st.subheader("🕵️ IP Investigator")
            ip_in = st.text_input("Enter IP Address...").strip()
            if ip_in:
                res = df_full[df_full['client_addr'] == ip_in]
                if not res.empty:
                    st.write(f"**{ip_in}** | {res.iloc[0]['country_name']} | {res.iloc[0]['asn']}")
                    
                    cs = CrowdSecManager()
                    cs_status = cs.get_ip_reputation(ip_in)
                    
                    col_inv1, col_inv2, col_inv3 = st.columns(3)
                    with col_inv1:
                        st.metric("Total Requests", len(res))
                        st.metric("Attack Events", len(res[res['is_attack'] == True]))
                    with col_inv2:
                        st.markdown("#### Intent Analysis")
                        if res.iloc[0]['is_bot']:
                            st.warning("🤖 Bot/Crawler")
                        elif (res['status_code'] >= 400).mean() > 0.5 and len(res) > 10:
                            st.error("🚨 Likely Scanner")
                        elif res['request_path'].nunique() > len(res) * 0.8 and len(res) > 5:
                            st.error("🔎 Path Enumerator")
                        elif len(res[res['is_attack'] == True]) > 0:
                            st.error("🔥 Malicious")
                        else:
                            st.success("✅ Legitimate")
                    
                    with col_inv3:
                        st.markdown("#### CrowdSec")
                        if cs_status:
                            st.error(f"🚫 Blocked: {cs_status.get('type')}")
                            if st.button(f"Unblock {ip_in}"):
                                if cs.unblock_ip(ip_in): st.rerun()
                        else:
                            st.success("✅ Not Blocked")
                            if st.button(f"Block {ip_in}"):
                                if cs.block_ip(ip_in): st.rerun()
                    
                    abuse_data = get_abuse_reputation(ip_in)
                    if abuse_data:
                        st.markdown("---")
                        a_col1, a_col2 = st.columns(2)
                        with a_col1:
                            score = abuse_data.get('abuseConfidenceScore', 0)
                            c_map = {"green": "#00CC96", "orange": "#FFA500", "red": "#EF545B"}
                            c = c_map["red"] if score > 50 else c_map["orange"] if score > 20 else c_map["green"]
                            st.markdown(f"**Abuse Score:** :{c}[{score}%]")
                            st.progress(min(score / 100, 1.0))
                        with a_col2:
                            st.write(f"Reports: {abuse_data.get('totalReports', 0)}")
                            st.write(f"Domain: {abuse_data.get('domain', 'N/A')}")
                    
                    st.markdown(f"[AbuseIPDB](https://www.abuseipdb.com/check/{ip_in}) | [Whois](https://who.is/whois-ip/ip-address/{ip_in})")
                    
                    with get_session() as session:
                        total_ip_logs = session.query(func.count(AccessLog.id)).filter(AccessLog.client_addr == ip_in).scalar()
                    
                    inv_page_size = 20
                    inv_total_pages = (total_ip_logs // inv_page_size) + (1 if total_ip_logs % inv_page_size > 0 else 0)
                    
                    if total_ip_logs > 0:
                        ic1, ic2 = st.columns([1, 4])
                        with ic1:
                            inv_page = st.number_input("Page", min_value=1, max_value=max(1, inv_total_pages), value=1, key="inv_page")
                        with ic2:
                            st.write(f"Page {inv_page} of {inv_total_pages}")
                        
                        with get_session() as session:
                            inv_query = select(AccessLog).filter(AccessLog.client_addr == ip_in).order_by(AccessLog.start_local.desc()).limit(inv_page_size).offset((inv_page-1)*inv_page_size)
                            hist_df = pd.read_sql(inv_query, engine)
                        st.dataframe(hist_df[['start_local', 'request_method', 'request_host', 'request_path', 'status_code', 'is_attack']], use_container_width=True)
                else: st.warning("IP not found")
    
    with tabs[4]:
            st.subheader("📺 Live Stream")
            st.caption("Latest 200 requests")
            live_df = df_full[['start_local', 'client_addr', 'country_code', 'request_host', 'request_path', 'status_code', 'is_attack']].head(200)
            st.dataframe(live_df, use_container_width=True)
            
            col_l1, col_l2 = st.columns(2)
            with col_l1: st.button("🔄 Refresh")
            with col_l2: st.download_button("📥 Export CSV", data=df.to_csv(index=False), file_name=f"traefik_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
    
    with tabs[5]:
            st.subheader("🏥 System Health")
            col_h1, col_h2 = st.columns(2)
            with col_h1:
                st.write("**Database**")
                try:
                    from sqlalchemy import text
                    with engine.connect() as conn:
                        db_size = conn.execute(text("SELECT pg_size_pretty(pg_database_size(current_database()))")).scalar()
                        row_count = conn.execute(text("SELECT count(*) FROM access_logs")).scalar()
                        earliest = conn.execute(text("SELECT min(start_local) FROM access_logs")).scalar()
                    st.info(f"Size: {db_size} | Rows: {row_count:,}")
                    st.info(f"Since: {earliest.strftime('%Y-%m-%d') if earliest else 'N/A'}")
                except Exception as e: st.error(f"DB Error: {e}")
                
                st.write("**Errors (4xx/5xx)**")
                err_df = df[df['status_code'] >= 400]
                if not err_df.empty:
                    st.write(f"Total: {len(err_df)} ({len(err_df)/len(df)*100:.1f}%)")
                    st.table(err_df['request_path'].value_counts().head(10))
                else:
                    st.success("No errors")
                
                st.write("**🚨 Threat Leaders (Highest Risk IPs)**")
                threat_df = get_threat_leaders(10)
                if not threat_df.empty:
                    st.dataframe(threat_df.rename(columns={
                        'client_addr': 'IP', 'total_threat': 'Threat Score', 
                        'requests': 'Reqs', 'country_code': 'Country', 'asn': 'ASN'
                    }), use_container_width=True)
                
                st.write("**🔐 Login Attempts (24h)**")
                login_attempts = get_login_attempts(24, 20)
                if login_attempts:
                    login_data = [{"IP": la.ip_address, "Path": la.path, "Status": la.status_code, "Time": la.timestamp.strftime("%H:%M"), "Country": la.country_code} for la in login_attempts]
                    st.table(pd.DataFrame(login_data))
                else:
                    st.success("No suspicious login attempts")
            
            with col_h2:
                st.write("**🌍 Geo Blocking**")
                blocked_countries = get_blocked_countries()
                if blocked_countries:
                    st.write("Blocked:", ", ".join([c.country_code for c in blocked_countries if c.active]))
                else:
                    st.info("No countries blocked")
                
                with st.form("block_country"):
                    country_code = st.text_input("Country Code (e.g., CN, RU)", max_chars=2).upper()
                    reason = st.text_input("Reason")
                    if st.form_submit_button("🚫 Block Country"):
                        if country_code and add_blocked_country(country_code, reason):
                            st.success(f"Blocked {country_code}")
                            st.rerun()
                
                with st.form("unblock_country"):
                    if blocked_countries:
                        unblock_country = st.selectbox("Unblock", [c.country_code for c in blocked_countries if c.active])
                        if st.form_submit_button("✅ Unblock"):
                            if remove_blocked_country(unblock_country):
                                st.success(f"Unblocked {unblock_country}")
                                st.rerun()
                
                st.write("**⚙️ Worker Stats (24h)**")
                worker_stats = get_worker_stats(24)
                if worker_stats:
                    total_logs = sum(s['logs_processed'] for s in worker_stats)
                    total_attacks = sum(s['attacks_detected'] for s in worker_stats)
                    total_banned = sum(s['ips_banned'] for s in worker_stats)
                    total_errors = sum(s['db_errors'] for s in worker_stats)
                    st.metric("Logs Processed", f"{total_logs:,}")
                    st.metric("Attacks Detected", f"{total_attacks:,}")
                    st.metric("IPs Banned", f"{total_banned:,}")
                    st.metric("DB Errors", f"{total_errors:,}")
                else:
                    st.info("No worker stats available")
                
                st.write("**Maintenance**")
                if st.button("🧹 Prune (Keep 30 days)"):
                    try:
                        from sqlalchemy import text
                        cutoff = datetime.now() - timedelta(days=30)
                        with engine.begin() as conn:
                            res = conn.execute(text("DELETE FROM access_logs WHERE start_local < :cutoff"), {"cutoff": cutoff})
                            st.success(f"Deleted {res.rowcount} rows")
                    except Exception as e: st.error(f"Prune failed: {e}")
                
                if st.button("🔄 Clear Cache"):
                    st.cache_data.clear()
                    CacheService.clear_all()
                    st.success("Cache cleared (Streamlit + Redis)")
                
                if st.button("📊 Update Precomputed Stats"):
                    update_precomputed_stats()
                    st.success("Stats updated")
    
    st.sidebar.markdown("---")
    st.sidebar.caption(f"Last: {datetime.now().strftime('%H:%M:%S')}")
    if st.sidebar.button("⚡ Refresh"): st.rerun()
