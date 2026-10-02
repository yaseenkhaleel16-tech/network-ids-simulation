# Network Intrusion Detection System (IDS) Simulation

A **defensive**, beginner-friendly hybrid IDS that analyses **synthetic network-flow records**, combines
rule-based, statistical-anomaly and (optional) machine-learning detection, raises explainable alerts, and gives
analysts a SOC-style dashboard for investigation and incident reporting.

> Safety: this project **never sends packets** and never touches a real network. Traffic is generated as data
> records using reserved documentation IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## Features
- Synthetic dataset generator (6,000 flows) and endless traffic simulator (`normal` / `mixed`, `slow` / `fast`)
- 15 engineered flow features with safe handling of bad input (invalid IPs/ports/protocols, zero duration, missing values)
- 6 configurable detection rules, z-score/IQR anomaly scoring, optional ML (Logistic Regression, Random Forest, Isolation Forest)
- Hybrid risk score 0-100 (configurable weights), alerts with severity, correlation into incidents
- SQLite storage, SOC dashboard (8 charts), live polling simulation, alert investigation, analyst notes, status workflow, downloadable incident report
- 36 automated tests

## Quick start (Windows PowerShell)
```
pip install -r requirements.txt
python data/generate_dataset.py
python -m ids.ml
python -m pytest -q
python -m streamlit run app.py
```
In the app: **Dashboard -> Load synthetic dataset**, then explore **Alerts & Investigation**, **Traffic Analytics**, **Live Simulation**.
Command-line simulator: `python -m ids.simulator --mode mixed --speed fast --count 10`

## How it works
Flow -> validate -> features -> [rules | anomaly | ML] -> hybrid risk score -> alert -> database -> dashboard -> analyst.

| Risk | Class | Severity |
|---|---|---|
| 0-20 | NORMAL | INFO |
| 21-40 | LOW RISK | LOW |
| 41-60 | SUSPICIOUS | MEDIUM |
| 61-80 | HIGH RISK | HIGH |
| 81-100 | CRITICAL INVESTIGATION | CRITICAL |

Weights: rules 40% / anomaly 30% / ML 30% (60/40 without ML). A strong rule match is never diluted below 85% of its own risk.
Thresholds, weights and rule limits are **project assumptions** (see `ids/config.py`) and would be calibrated in a real SOC.

## Honest limitations
- Data is synthetic and generated from templates, so ML metrics are better than real-world traffic would give. Check `reports/ml_metrics.json` for the numbers computed on your run.
- The ML model does not see destination ports (per the project brief), so port-based rules cover what ML cannot.
- Mild or "low and slow" patterns can slip under rule thresholds (false negatives); changing normal behaviour can raise false positives.
- Flow records include pre-aggregated `unique_destination_ports/ips` (what a flow aggregator would provide).
- This is a learning simulation, not a replacement for Suricata, Snort or a production SIEM.

## Project layout
`app.py` dashboard | `ids/` engine (validation, features, rules, anomaly, ml, pipeline, alerts, database, report, simulator) | `data/generate_dataset.py` | `tests/` | `models/`, `reports/`, `screenshots/`

## Future work
Real PCAP/NetFlow ingestion in an isolated lab, Suricata rule import, MITRE ATT&CK mapping, REST API, threat-intel enrichment, analyst-feedback retraining.
