# Network Traffic Monitoring System

A self-contained network monitoring system built with Python, combining passive packet capture, persistent flow-level storage, live dashboards, active reachability probing, unsupervised anomaly detection, and a custom web interface — designed for small organizations that want real visibility into their network without depending on a cloud service.

Built as a diploma thesis project at **New Bulgarian University**, Telecommunications and Computer Technologies program.

> 📄 Full technical documentation (120+ pages, including complete source code, test results, and screenshot-documented validation) is available in the accompanying thesis document.

---

## What it does

- **Captures live network traffic** and computes throughput, packet rate, protocol distribution, top talkers, and Shannon entropy of source-IP / destination-port distributions
- **Detects port scans and volumetric anomalies** using an unsupervised Isolation Forest model — validated against a real Nmap scan (independently rediscovered from unlabeled data) and a real traffic burst (correctly distinguished from a scan by entropy signature alone)
- **Actively probes reachability** (RTT, jitter, packet loss) to a configurable set of targets — metrics passive capture structurally cannot provide
- **Stores everything queryably** in SQLite using a NetFlow-style unidirectional flow model, so questions not anticipated in advance can still be answered with plain SQL
- **Visualizes live and historical data** via Prometheus + Grafana, plus a custom-built web console
- **Generates automated periodic reports** and **sends live alerts** via Grafana on SYN-rate spikes, entropy anomalies, ML-flagged anomalies, and probe failures

---

## Architecture

```
                    +------------------+
   Network Card --> |  Npcap / libpcap |
                    +---------+--------+
                              |
                              v
                    +------------------+        +---------------+
                    |  Scapy capture   |------->|    SQLite     |
                    |  engine          |        |  (flows,      |
                    +---------+--------+        |   metrics)    |
                              |                  +-------+-------+
                              v                          |
                    +------------------+                 |
                    |   Prometheus     |<-----------------+
                    |   exporter       |
                    +---------+--------+
                              v
                    +------------------+        +-------------------+
                    | Prometheus +     |        |  FastAPI backend  |
                    | Grafana          |        |  + web console    |
                    +------------------+        +-------------------+

   Independent subsystems running alongside the above:
   +--------------------+  +------------------------+  +----------------------+
   | Active probing     |  | Isolation Forest        |  | Automated report      |
   | (RTT/jitter/loss)  |  | anomaly detector         |  | generator              |
   +--------------------+  +------------------------+  +----------------------+

   Live alerting (Grafana, threshold rules on SYN-rate, entropy, and anomaly
   signals) was also built and validated during development but is not
   included in this public repository - see the thesis documentation for
   the full alerting configuration and setup guide.
```

SQLite is the single source of detailed truth; Prometheus handles aggregated time-series data for dashboarding. The two are kept deliberately separate — see the thesis documentation, Section 2.7, for the reasoning.

---

## Repository structure

```
|-- capture/            # Phases 1-3: live capture, storage, Prometheus export
|   |-- capture_metrics.py
|   |-- capture_storage.py
|   `-- capture_exporter.py
|-- probing/            # Phase 4: active RTT/jitter/loss probing
|   `-- active_probe.py
|-- anomaly/            # Phase 5: Isolation Forest anomaly detection
|   `-- anomaly_detector.py
|-- throughput/         # Phase 6: throughput accuracy validation
|   |-- loadgen.py
|   `-- throughput_compare.py
|-- web/                # Phase 7: REST API, web console, reporting
|   |-- api.py
|   |-- queries.py
|   |-- report_generator.py
|   `-- console.html
|-- common/
|   `-- network_utils.py    # gateway/interface auto-detection
`-- config/
    |-- prometheus.yml
    `-- targets.txt
```

---

## Requirements

- Windows (developed/tested on) or Linux
- Python 3.10+
- [Npcap](https://npcap.com/) (Windows) - install with "WinPcap API-compatible Mode" enabled
- [Nmap](https://nmap.org/) (optional, for generating test traffic)
- [Prometheus](https://prometheus.io/download/) and [Grafana](https://grafana.com/grafana/download) (native binaries, no Docker required)

```bash
pip install scapy prometheus_client scikit-learn joblib fastapi uvicorn
```

---

## Quick start

**1. Passive capture** (interface and gateway auto-detected):
```bash
python capture/capture_exporter.py --window 5 --db netmon.db --exporter-port 8000
```

**2. Active probing:**
```bash
python probing/active_probe.py --targets config/targets.txt --interval 30 --db netmon.db --exporter-port 8001
```

**3. Train and run the anomaly detector:**
```bash
python anomaly/anomaly_detector.py --mode train --db netmon.db --model model.joblib
python anomaly/anomaly_detector.py --mode watch --db netmon.db --model model.joblib --exporter-port 8002
```

**4. Web interface:**
```bash
python web/api.py --db netmon.db --port 8080
# then open web/console.html via a local HTTP server (not file://, see docs for why)
```

**5. Prometheus + Grafana**, pointed at `config/prometheus.yml`, with the Grafana dashboard JSON imported per the setup guide in the thesis documentation (Section 6).

---

## Key validated results

- A controlled Nmap scan produced the theoretically predicted entropy signature (destination-port entropy ~doubled, source-IP entropy collapsed) - confirmed live, then independently triangulated three ways from stored flow data alone, then **independently rediscovered by the unsupervised anomaly detector from 1,598 unlabeled windows**.
- A real, unprompted traffic burst (five simultaneous video streams) was correctly flagged as anomalous by volume, while entropy divergence correctly distinguished it from a scan signature - demonstrating the combined feature set discriminates *categories* of anomaly, not just "unusual."
- Throughput accuracy was measured directly against a controlled generator: accurate at normal traffic rates (a few hundred packets/second); a genuine capture-engine packet-rate ceiling was identified and documented at ~4,000+ pkt/s.

Full methodology, screenshots, the complete functional test suite, and eighteen documented troubleshooting case studies are in the thesis documentation.

---

## Author

**Stanislav Peltekov**
New Bulgarian University - Telecommunications and Computer Technologies
Supervisor: доц. Георги Петров
2026