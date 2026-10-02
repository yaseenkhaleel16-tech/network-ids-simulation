"""Network IDS Simulation - SOC dashboard (Streamlit).  Run:  python -m streamlit run app.py
All data is SYNTHETIC. No packets are sent and no real network is touched."""
from datetime import datetime, timedelta, timezone
import os

import pandas as pd
import streamlit as st

from ids import database as db
from ids.alerts import correlate_alerts
from ids.anomaly import load_or_build_baseline, moving_average
from ids.config import SEVERITIES, STATUSES
from ids.pipeline import process_flows
from ids.report import make_incident_report
from ids.simulator import FlowSimulator

st.set_page_config(page_title="Network IDS Simulation", page_icon="🛰️", layout="wide")
PAGES = ["Dashboard", "Live Simulation", "Alerts & Investigation", "Traffic Analytics", "Learn"]
page = st.sidebar.radio("Menu", PAGES)
st.sidebar.caption("Educational simulation. Synthetic data only - no packets are sent.")
RANGES = {"All": None, "Last 15 min": 15, "Last 1 hour": 60, "Last 6 hours": 360, "Last 24 hours": 1440}


@st.cache_resource
def baseline():
    return load_or_build_baseline()


def since(label):
    m = RANGES[label]
    return None if m is None else (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=m)).isoformat(timespec="seconds")


def flows_df(since_ts=None):
    df = pd.DataFrame(db.list_flows(since=since_ts))
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def alerts_df(**kw):
    df = pd.DataFrame(db.list_alerts(**kw))
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def load_dataset(path="data/network_traffic.csv"):
    if not os.path.exists(path):
        st.error("Dataset not found. Run:  python data/generate_dataset.py")
        return
    rows = pd.read_csv(path).to_dict("records")
    bar, ins = st.progress(0.0, text="Analysing flows..."), 0
    for i in range(0, len(rows), 500):
        out = db.save_results(process_flows(rows[i:i + 500], baseline=baseline()))
        ins += out["flows_inserted"]
        bar.progress(min((i + 500) / len(rows), 1.0))
    st.success(f"Analysed {len(rows)} flows ({ins} new).")


if page == "Dashboard":
    st.title("🛰️ SOC Dashboard")
    stats = db.get_stats()
    if stats["total_flows"] == 0:
        st.info("No data yet. Load the synthetic dataset, or open Live Simulation.")
        if st.button("Load synthetic dataset (6,000 flows)", type="primary"):
            load_dataset()
            st.rerun()
    else:
        c = st.columns(6)
        for col, (lab, key) in zip(c, [("Total flows", "total_flows"), ("Normal", "normal"), ("Suspicious", "suspicious"),
                                       ("Open alerts", "open_alerts"), ("Critical alerts", "critical_alerts"), ("Avg risk", "avg_risk")]):
            col.metric(lab, stats[key])
        f, a = flows_df(), alerts_df()
        r1, r2 = st.columns(2)
        r1.subheader("1. Traffic over time")
        r1.line_chart(f.set_index("timestamp").resample("10min").size())
        r2.subheader("2. Normal vs suspicious")
        r2.bar_chart(f["traffic_class"].value_counts())
        r3, r4 = st.columns(2)
        if not a.empty:
            r3.subheader("3. Alerts by severity")
            r3.bar_chart(a["severity"].value_counts().reindex(SEVERITIES).dropna())
            r4.subheader("4. Top alert types")
            r4.bar_chart(a["alert_type"].value_counts().head(8))
        r5, r6 = st.columns(2)
        r5.subheader("5. Protocol distribution")
        r5.bar_chart(f["protocol"].value_counts())
        r6.subheader("6. Destination port distribution")
        r6.bar_chart(f["destination_port"].astype(str).value_counts().head(10))
        r7, r8 = st.columns(2)
        if not a.empty:
            r7.subheader("7. Top source IPs by alerts")
            r7.bar_chart(a["source_ip"].value_counts().head(10))
        r8.subheader("8. Risk score distribution")
        r8.bar_chart(pd.cut(f["risk_score"], [-1, 20, 40, 60, 80, 100], labels=["0-20", "21-40", "41-60", "61-80", "81-100"]).value_counts().sort_index())
        st.subheader("Recent alerts")
        if not a.empty:
            st.dataframe(a.head(15)[["timestamp", "source_ip", "destination_ip", "protocol", "alert_type", "severity", "risk_score", "status"]], use_container_width=True)
        with st.expander("Danger zone"):
            if st.checkbox("I understand this deletes all stored flows and alerts") and st.button("Reset database"):
                db.clear_all()
                st.rerun()

elif page == "Live Simulation":
    st.title("📡 Live Simulation")
    st.caption("Simulator -> IDS engine -> alert engine -> database. Refresh method: polling (simplest for beginners).")
    c1, c2, c3 = st.columns(3)
    mode = c1.selectbox("Traffic mode", ["mixed", "normal"])
    per_tick = c2.slider("Flows per refresh", 1, 20, 5)
    interval = c3.slider("Refresh every (seconds)", 1, 10, 2)
    st.toggle("▶ Run live simulation", key="live")
    if st.session_state.get("sim_mode") != mode:
        st.session_state.sim, st.session_state.sim_mode = FlowSimulator(mode), mode

    def tick():
        if st.session_state.get("live"):
            res = process_flows([st.session_state.sim.next_flow() for _ in range(per_tick)], baseline=baseline())
            db.save_results(res)
            st.session_state.last = res
        last = st.session_state.get("last", [])
        if last:
            st.dataframe(pd.DataFrame([{"time": r["flow"]["timestamp"], "source": r["flow"]["source_ip"], "destination": r["flow"]["destination_ip"],
                                        "proto": r["flow"]["protocol"], "port": r["flow"]["destination_port"], "risk": r["risk_score"],
                                        "class": r["traffic_class"], "alert": r["alert_type"] if r["risk_score"] >= 41 else "-",
                                        "simulator truth": r["flow"]["scenario_type"]} for r in last]), use_container_width=True)
        s = db.get_stats()
        st.write(f"**Stored:** {s['total_flows']} flows | {s['open_alerts']} open alerts | avg risk {s['avg_risk']}")

    (st.fragment(run_every=interval if st.session_state.get("live") else None)(tick) if hasattr(st, "fragment") else tick)()

elif page == "Alerts & Investigation":
    st.title("🚨 Alerts & Investigation")
    c = st.columns(5)
    sev = c[0].selectbox("Severity", ["All"] + SEVERITIES[1:])
    proto = c[1].selectbox("Protocol", ["All", "TCP", "UDP", "ICMP"])
    stat = c[2].selectbox("Status", ["All"] + STATUSES)
    rng = c[3].selectbox("Time range", list(RANGES), index=0)
    types = sorted({a["alert_type"] for a in db.list_alerts(limit=5000)})
    atype = c[4].selectbox("Alert type", ["All"] + types)
    alerts = db.list_alerts(severity=None if sev == "All" else sev, protocol=None if proto == "All" else proto,
                            status=None if stat == "All" else stat, alert_type=None if atype == "All" else atype, since=since(rng))
    st.write(f"**{len(alerts)} alerts**")
    if alerts:
        st.dataframe(pd.DataFrame(alerts)[["alert_id", "timestamp", "source_ip", "destination_ip", "protocol", "alert_type", "severity", "risk_score", "status"]].head(300), use_container_width=True)
        with st.expander("Correlated incidents (same source + type within 60 s)"):
            inc = correlate_alerts(alerts)
            st.write(f"{len(alerts)} alerts grouped into {len(inc)} incidents")
            st.dataframe(pd.DataFrame(inc).drop(columns=["alert_ids"]).sort_values("max_risk", ascending=False).head(100), use_container_width=True)
        pick = st.selectbox("Open alert for investigation", [a["alert_id"] for a in alerts[:300]])
        al = db.get_alert(pick)
        d = al["details"]
        st.subheader(f"{al['alert_id']} - {al['alert_type']}")
        m = st.columns(4)
        m[0].metric("Severity", al["severity"])
        m[1].metric("Final risk", f"{al['risk_score']}/100")
        m[2].metric("Anomaly score", d.get("anomaly_score", 0))
        ml = d.get("ml_probability")
        m[3].metric("ML score", "off" if ml is None else f"{ml:.0%}")
        st.write(f"**Source:** {al['source_ip']}:{al['source_port']} → **Destination:** {al['destination_ip']}:{al['destination_port']} ({al['protocol']}) at {al['timestamp']}")
        st.write(f"**Why:** {al['description']}")
        st.write("**Matched rules:** " + (", ".join(f"{x['rule_id']} {x['name']}" for x in d.get("matches", [])) or "none (statistical/ML detection)"))
        with st.expander("Traffic statistics"):
            st.json(d.get("features", {}))
        from ids.alerts import INVESTIGATION_STEPS
        st.write("**Recommended investigation steps**")
        for s in INVESTIGATION_STEPS.get(al["alert_type"], INVESTIGATION_STEPS["default"]):
            st.write("- " + s)
        st.divider()
        new = st.selectbox("Status", STATUSES, index=STATUSES.index(al["status"]))
        note = st.text_area("Analyst note", max_chars=1000)
        if st.button("Save update", type="primary"):
            try:
                if new != al["status"]:
                    db.update_status(pick, new, note)
                elif note.strip():
                    db.add_note(pick, note)
                st.rerun()
            except ValueError as e:
                st.error(str(e))
        st.write("**Incident timeline**")
        for t in db.get_timeline(pick):
            st.write(f"`{t['created_at']}` [{t['note_type']}] {t['note']}")
        st.download_button("Download incident report (.md)", make_incident_report(al, db.get_timeline(pick)), file_name=f"{pick}_report.md")
    else:
        st.info("No alerts match. Load data on the Dashboard page or run the Live Simulation.")

elif page == "Traffic Analytics":
    st.title("📈 Traffic Analytics")
    f = flows_df()
    if f.empty:
        st.info("No data yet - load the dataset on the Dashboard page.")
    else:
        smooth = st.checkbox("Show moving average", value=True)
        win = st.slider("Moving-average window (minutes)", 2, 20, 5)
        f["pps"] = f["packet_count"] / f["duration_seconds"].clip(lower=0.1)
        f["bps"] = f["byte_count"] / f["duration_seconds"].clip(lower=0.1)
        g = f.set_index("timestamp").resample("1min")
        series = {"Packets per second (avg)": g["pps"].mean(), "Bytes per second (avg)": g["bps"].mean(),
                  "Connections per minute": g["connection_count"].sum(), "Failed connections per minute": g["failed_connection_count"].sum(),
                  "Average risk per minute": g["risk_score"].mean()}
        a = alerts_df()
        if not a.empty:
            series["Alerts per minute"] = a.set_index("timestamp").resample("1min").size()
        notes = {"Packets per second (avg)": "Spikes can mean floods or scans.", "Bytes per second (avg)": "Sustained spikes may mean large transfers or exfiltration.",
                 "Connections per minute": "Bursts suggest scanning or brute force.", "Failed connections per minute": "Rising failures hint at password guessing or probing.",
                 "Average risk per minute": "Shows when the IDS was most worried.", "Alerts per minute": "Shows the alert workload for analysts."}
        cols = st.columns(2)
        for i, (name, s) in enumerate(series.items()):
            s = s.fillna(0)
            if smooth:
                s = pd.Series(moving_average(list(s), win), index=s.index)
            cols[i % 2].subheader(name)
            cols[i % 2].line_chart(s)
            cols[i % 2].caption(notes[name])

else:
    st.title("🎓 Learn: IDS Basics")
    st.markdown("""
**Flow vs packet:** a *packet* is one small message; a *flow* summarises many packets between two endpoints (this project works on flows).

**Event → Alert → Incident:** an *event* is one observation, an *alert* is a detection that needs attention, an *incident* groups related alerts.

**IDS vs IPS:** an IDS *detects and alerts*; an IPS sits in the traffic path and can also *block*.

**NIDS vs HIDS:** network-based IDS watches traffic; host-based IDS watches one computer's logs and files. This project simulates a *network-based hybrid IDS*.

| | Signature / rule | Anomaly |
|---|---|---|
| Idea | Known bad pattern | Deviation from normal baseline |
| Strength | Clear, explainable | Can catch unseen behaviour |
| Weakness | Misses new or mild patterns | False positives when normal changes |

**Risk score:** rules 40% + anomaly 30% + ML 30% (60/40 without ML). A strong rule match is never diluted below 85% of its own risk.

**False positive:** harmless traffic flagged. **False negative:** real attack missed. Tuning thresholds trades one for the other.

⚠️ A detection is a lead to investigate, not proof of malicious activity. Scores and thresholds are project assumptions.
""")
