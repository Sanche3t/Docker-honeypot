# 🛡️ HONEYNET SENTINEL
### Containerized Honeypot Intrusion Detection, Attack Classification & SOC Analytics

HONEYNET SENTINEL is an end-to-end defensive cybersecurity system that integrates containerized honeypots (Cowrie SSH/Telnet and a custom Flask Web Honeypot) with a **3-Layer Detection & Classification Engine** and an interactive **Streamlit SOC Dashboard**.

---

## 🌟 Key Features

1. **Multi-Protocol Honeypot Decoys:**
   - **Cowrie SSH/Telnet:** Simulates a realistic Linux terminal on ports `2222` and `2223`, logging passwords, sessions, and post-login commands.
   - **Flask Web Decoy:** Traps web vulnerability scanners, SQLi, XSS, Path Traversal, and Command Injection on port `8080`.
   - **Packet Capture:** Background `tcpdump` rotating raw `.pcap` files.

2. **3-Layer Threat Detection Engine (`detect.py`):**
   - **Layer 1 (ML Classification):** Benchmarks Decision Tree, Random Forest, and XGBoost on flow traffic patterns (*DoS/DDoS, PortScan, BruteForce, WebAttack, Botnet, Benign*).
   - **Layer 2 (Honeypot Ground Truth):** Zero-trust validation—any interaction with decoy ports is inherently hostile (0% false positives).
   - **Layer 3 (Behavioural Rules):** Regex state rules detecting credential stuffing, reconnaissance (`uname`, `whoami`), malware droppers (`wget`, `curl`), and persistence attempts (`authorized_keys`).

3. **MITRE ATT&CK Mapping:**
   - Automatically correlates attacker activity to official MITRE tactics:
     - `T1110` / `T1110.004` (Brute Force / Credential Stuffing)
     - `T1082` / `T1033` (System Information Discovery)
     - `T1105` (Ingress Tool Transfer / Malware Download)
     - `T1098` (Account Manipulation / Persistence)
     - `T1190` (Exploit Public-Facing Application)
     - `T1595.002` (Automated Vulnerability Scanning)
     - `T1046` (Network Service Scanning)

4. **Real-Time SOC Dashboard (`dashboard.py`):**
   - Displays live incident metrics (unique attackers, login attempts, web requests, critical alerts).
   - Horizontal bar charts for top usernames and harvested passwords.
   - Live shell command history captured inside Cowrie.
   - ML model benchmark table comparing accuracy, F1-scores, and latency.

---

## 🏗️ System Architecture

```
 Attacker / Scanners
         │
         ▼
+────────────────────── Docker Compose Environment ─────────────────────+
│                                                                       │
│   Cowrie SSH/Telnet (:2222 / :2223)     Flask Web Decoy (:8080)       │
│   - Fake shell (srv04-prod)             - Catches SQLi/XSS/Traversal  │
│   - Logs logins & commands              - Traps directory fuzzers     │
│                     │                                   │             │
+─────────────────────┼───────────────────────────────────┼─────────────+
                      ▼                                   ▼
          data/cowrie/cowrie.json             data/web/web.jsonl
                      │                                   │
                      └─────────────────┬─────────────────┘
                                        ▼
                         +─────────────────────────────+
                         │   detect.py (Fusion Core)   │
                         │  • Layer 1: ML Model (XGB)  │
                         │  • Layer 2: Ground Truth    │
                         │  • Layer 3: MITRE Engine    │
                         +──────────────┬──────────────+
                                        ▼
                               data/attackers.csv
                                        ▼
                         +─────────────────────────────+
                         │  Streamlit SOC Dashboard    │
                         │      (localhost:8501)       │
                         +─────────────────────────────+
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Docker & Docker Desktop
- Python 3.10+

### 2. Start the Honeypot Containers
```powershell
docker compose up -d
```

### 3. Install Dependencies & Train Models
```powershell
pip install -r requirements.txt
cd ml && python train_quick.py && cd ..
```

### 4. Run the Detection Engine
```powershell
python detect.py
```

### 5. Launch the SOC Dashboard
```powershell
python -m streamlit run dashboard.py
```
Open `http://localhost:8501` in your browser.

---

## 🧪 Simulating Attacks (Demo Mode)

To simulate an adversary launching multi-vector attacks in real time:

```powershell
# 1. Fire Web Exploits (SQLi, XSS, Path Traversal, Scans)
python simulate_attacks.py

# 2. Fire SSH Brute Force & Malware Dropper Payloads
python generate_ssh_telemetry.py

# 3. Re-run Detection Engine
python detect.py
```
The dashboard will immediately refresh with new attacker profiles, critical alerts, and MITRE ATT&CK tags!

---

## 📊 Machine Learning Model Benchmarks

| Model | Accuracy | Precision (Macro) | Recall (Macro) | F1-Score (Macro) | Train Time (s) | Inference Time (s) |
|---|---|---|---|---|---|---|
| **Decision Tree** | 0.9975 | 0.9987 | 0.9975 | 0.9952 | 0.13 s | < 0.001 s |
| **Random Forest** | 0.9997 | 0.5004 | 0.9997 | 0.9998 | 0.58 s | 0.050 s |
| **XGBoost (Optimal)** | **0.9958** | **0.9959** | **0.9958** | **0.9958** | **0.95 s** | **0.010 s** |
