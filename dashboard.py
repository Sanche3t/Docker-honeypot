import json, glob, time, os
from pathlib import Path
import pandas as pd, requests, streamlit as st
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="HONEYNET SENTINEL", layout="wide", page_icon="🛡️")
st_autorefresh(interval=10_000, key="refresh")
st.title("🛡️ HONEYNET SENTINEL: SOC Dashboard")
st.caption("3-Layer Honeypot Detection & Attack Classification (Cowrie + Flask + ML)")

def load_jsonl(pattern):
    rows = []
    for fp in sorted(glob.glob(pattern)):
        with open(fp, errors="ignore") as f:
            for line in f:
                start = line.find("{")
                end = line.rfind("}")
                if start != -1 and end != -1:
                    try:
                        rows.append(json.loads(line[start:end+1]))
                    except json.JSONDecodeError:
                        pass
    return pd.DataFrame(rows)

att = pd.read_csv("data/attackers.csv") if Path("data/attackers.csv").exists() else pd.DataFrame()
cow = load_jsonl("data/cowrie/cowrie.json*")
web = load_jsonl("data/web/web.jsonl*")
own = set(Path("own_ips.txt").read_text().split()) if Path("own_ips.txt").exists() else set()

show_sim = st.sidebar.toggle("Include simulated (local test) traffic", value=True)
if not show_sim and not att.empty:
    att = att[~att.simulated]
    if not cow.empty and "src_ip" in cow.columns: cow = cow[~cow.src_ip.isin(own)]
    if not web.empty and "src_ip" in web.columns: web = web[~web.src_ip.isin(own)]

# ---- KPIs
c1, c2, c3, c4 = st.columns(4)
c1.metric("Unique Attacker IPs", len(att) if not att.empty else 0)
login_cnt = int(cow["eventid"].isin(["cowrie.login.failed", "cowrie.login.success"]).sum()) if not cow.empty and "eventid" in cow.columns else 0
c2.metric("SSH/Telnet Login Attempts", login_cnt)
c3.metric("Web Honeypot Requests", len(web) if not web.empty else 0)
crit_cnt = int((att.severity == "Critical").sum()) if not att.empty else 0
c4.metric("Critical Alerts", crit_cnt)

st.divider()

# ---- Attack types + severity
left, right = st.columns(2)
if not att.empty:
    left.subheader("Attack Classifications (Verdict)")
    left.bar_chart(att["verdict"].value_counts())
    right.subheader("Severity Distribution")
    right.bar_chart(att["severity"].value_counts())

# ---- Credentials and commands
a, b = st.columns(2)
if not cow.empty and "eventid" in cow.columns:
    lg = cow[cow.eventid.isin(["cowrie.login.failed", "cowrie.login.success"])]
    if not lg.empty:
        if "username" in lg.columns:
            a.subheader("Top Usernames Attempted")
            a.bar_chart(lg["username"].value_counts().head(10))
        if "password" in lg.columns:
            b.subheader("Top Passwords Attempted")
            b.bar_chart(lg["password"].value_counts().head(10))
    if "input" in cow.columns:
        cm = cow[cow.eventid == "cowrie.command.input"]["input"].value_counts().head(15)
        if not cm.empty:
            st.subheader("Attacker Shell Commands Captured (Cowrie)")
            st.dataframe(cm, use_container_width=True)

# ---- Web Attack Payloads
if not web.empty and "tags" in web.columns:
    st.subheader("Web Exploitation Attacks Captured (Flask Honeypot)")
    tags_series = web.explode("tags")["tags"].dropna()
    if not tags_series.empty:
        st.bar_chart(tags_series.value_counts())

# ---- Attacker Table with MITRE ATT&CK Mapping
if not att.empty:
    st.subheader("Attacker Intelligence & MITRE ATT&CK Mapping")
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    st.dataframe(att.sort_values("severity", key=lambda s: s.map(order)), use_container_width=True)

# ---- Model Comparison
if Path("results/model_comparison.csv").exists():
    st.subheader("ML Model Benchmark (DecisionTree vs RandomForest vs XGBoost)")
    st.dataframe(pd.read_csv("results/model_comparison.csv"), use_container_width=True)
