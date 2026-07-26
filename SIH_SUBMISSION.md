# 📋 Smart India Hackathon (SIH) Project Submission & Idea Details

This document contains the official SIH idea submission details for **Problem Statement ID 3**.

---

## 1. Hackathon Registration & Metadata

*   **Problem Statement ID**: 3
*   **Problem Statement Title**: AI-Powered Behavioral Anomaly Detection for Cybersecurity
*   **Theme**: Artificial Intelligence & Cybersecurity
*   **PS Category**: Software
*   **Student Name**: Resu Abhinay
*   **Student ID**: 23BAI10545

---

## 2. Challenge & Solution Overview

### The Challenge
*   **Signature-Based Limitations**: Static intrusion detection systems (IDS) miss zero-day exploits, subtle lateral movements, and credential abuse.
*   **Severe Class Imbalance**: Anomaly incidents represent $<3\%$ of total enterprise network traffic.
*   **Concept Drift & Cold Start**: Employee routine changes cause false-positive spikes; new entities lack historical baselines.

### Our Solution
*   **Zero-Day Identification**: Unsupervised Isolation Forest isolates unknown deviations without predefined attack signatures.
*   **Multi-Class Threat Profiling**: XGBoost categorizes incidents into specific threat vectors (Brute Force, Impossible Travel, Lateral Movement, etc.).
*   **Explainable Risk Engine**: Outputs dynamic risk scores (0–100) and plain-English attributions via SHAP TreeExplainer.

---

## 3. Technical Approach & Architecture

*   **Data Ingestion & Profiling**: Synthetic telemetry generator modeling 500+ entities across 25,000+ chronological logs. Calculates continuous deviations for hours, IPs, devices, and resource scopes.
*   **Sequential Feature Engineering**: Tracks time-aware lag metrics including `login_velocity_kmh`, `country_change`, `device_novelty`, and `resource_entropy_1h`.
*   **Hybrid Detection Pipeline**:
    *   *Unsupervised (Isolation Forest)*: Evaluates baseline deviations for zero-day detection.
    *   *Supervised (XGBoost)*: Classifies anomalies across attack categories.
*   **Operational Readiness Controls**:
    *   *Cold Start Handling*: Maps new users/devices ($< 5$ events) to peer-group baselines (e.g., HR, Engineering).
    *   *Concept Drift Handling*: Adapts baseline profiles via Exponential Moving Averages ($\alpha = 0.05$) and monitors Population Stability Index (PSI $> 0.25$).

---

## 4. Feasibility and Viability

*   **Threat Recall (False Negative Rate)**: $0.00\%$ (Zero missed threats evaluated on 6,133 held-out chronological test events).
*   **Average Inference Latency**: $< 8.5\text{ ms}$ per event (Real-time capability).
*   **Multi-Class Classification Accuracy**: $66.87\%$
*   **Offline Training Duration**: $\approx 15\text{ seconds}$ (25,000 baseline records).
*   **False Positive Reduction**: Integrates active feedback loops to allow analysts to mark false alarms and dynamically adjust baseline profiles.
*   **High ROI**: Open-source foundation with low infrastructure footprint and sub-10ms response times.

---

## 5. Artifacts & SOC Capabilities

### Module Breakdown
*   `ml/generator.py`: Generates baseline normal telemetry and controlled threat injections.
*   `ml/dataset.py`: Extracts sequential lag features and spatial-temporal vectors.
*   `models/profiling_engine.py`: Constructs behavioral baselines with Cold Start and Drift EMA support.
*   `models/risk_scorer.py`: Calculates composite risk metrics (0–100) and maps business impacts.
*   `streamlit_app.py`: Interactive dark enterprise Security Operations Center (SOC) workspace.

### SOC Dashboard Capabilities
*   **Executive Overview**: High-level KPIs, real-time threat counts, and alert distribution charts.
*   **Live Threat Queue**: Chronological event stream displaying risk scores and threat categories.
*   **Incident Workspace**: Interactive travel vector maps, SHAP feature importance charts, and prescriptive response playbooks.
*   **System Health Monitor**: Real-time Population Stability Index (PSI) tracking and drift injection controls.

---

## 6. Research & References

### Core ML Methodologies
*   Liu, F. T., Ting, K. M., & Zhou, Z. H. *"Isolation Forest"* (IEEE ICDM).
*   Chen, T., & Guestrin, C. *"XGBoost: A Scalable Tree Boosting System"* (ACM SIGKDD).
*   Lundberg, S. M., & Lee, S. I. *"A Unified Approach to Interpreting Model Predictions"* (NeurIPS / SHAP).
