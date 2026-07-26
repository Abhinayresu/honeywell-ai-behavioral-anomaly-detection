# 📋 Report: Assumptions, Metrics & Known Limitations

This report documents the core operational assumptions, system metrics, and known limitations of the Honeywell AI-Powered Behavioral Anomaly Detection System.

---

## 1. Assumptions

*   **Behavioral Continuity**: It is assumed that enterprise entities (Users, Service Accounts, Edge Devices) maintain relatively stable access habits (e.g., standard login hour ranges, trusted source IPs, preferred browsers, and authorized resource scopes).
*   **Normal Telemetry Dominance**: We assume that normal telemetry accounts for the vast majority (>97%) of the daily access logs, which is a prerequisite for training the unsupervised Isolation Forest.
*   **Sequential Context Requirement**: Static log snapshots are insufficient. We assume that threats like Brute Force, Impossible Travel, and Lateral Movement can only be resolved by tracking the chronological state (lag differences) per entity.
*   **MFA and Device Spoofing**: We assume that while credentials may be compromised, copying the hardware browser fingerprint and user-agent string perfectly is difficult for casual attackers.

---

## 2. System Metrics

The system was evaluated on a held-out chronological test dataset of 6,133 events:

*   **Multi-Class Classification Accuracy**: `66.87%`
*   **Threat Recall (FNR)**: `0.000%` (Zero threats missed on the test dataset).
*   **False Positive Rate (FPR)**: `38.65%` (Highly conservative security gating, optimized to prevent severe exploits. Can be reduced to `22.4%` under strict confidence calibration).
*   **Inference Latency**: `< 8.5 ms` per event.
*   **Offline Training Duration**: `~ 15 seconds` for 25,000 baseline records.

---

## 3. Known Limitations

*   **User-Agent Fingerprint Spoofing**: Highly sophisticated threat actors can capture and replay legitimate user-agent strings, which would bypass the device novelty indicator.
*   **Sudden Concept Drift**: While the system uses Exponential Moving Averages (EMA) with a decay factor $\alpha=0.05$ to adapt to gradual habits shifts (daylight savings, home IP adjustments), sudden operational shifts (e.g., office relocations or emergency restructuring) will trigger false positive spikes until the PSI drift monitor prompts a full model retraining.
*   **Cold Start Bootstrap Delay**: During the initial bootstrap period ($N < 5$ events), the system falls back to the department/entity-type peer template. While this prevents security gaps, it cannot detect highly specific, personalized anomalies until the user accumulates individual history.
*   **Unlabeled Attack Variants**: The supervised XGBoost classifier relies on training targets to identify specific attack classes (e.g. Brute Force vs. Lateral Movement). Unseen zero-day attack variants will be flagged as anomalies by the Isolation Forest but may be classified as "Normal" or misclassified under XGBoost unless updated training targets are provided.
