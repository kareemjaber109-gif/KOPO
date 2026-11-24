# KOPO ThreatNet: Phase 1 Research Baseline Report & Audit Findings
**Run ID:** `run_clean_benchmark_v1`  
**Date:** 2026-11-24  
**Status:** `RESEARCH BASELINE (NOT CERTIFIED - PHASE 1 INCOMPLETE / OPEN AUDIT ITEMS)`  
**Model Origin:** `REAL` (Trained strictly on CIC-IDS2017 Train Block)  
**External Hold-out Validation:** `CSE-CIC-IDS2018` (162,658 sampled flows) & `UNSW-NB15`  

---

## 1. Executive Summary & Review Alignment

- **Certification Status:** Retained strictly as a **Research Baseline (`certified: false`)**. Phase 1 is **NOT CLOSED**. Phase 2 (Alert aggregation, incident DB, backend API) remains **strictly blocked**.
- **Test Set Governance & Burn Notice:** The held-out sequential Test block (219,975 flows) was evaluated **at least 5 times** across development and audit iterations (see Section 6). Consequently, the Test block is officially declared **burned for hyperparameter selection**.
- **Model Selection Rule (Val Only):**
  - **Date:** 2026-11-24.
  - **Rule:** Select model with highest Macro-F1 strictly on the **Validation block** ($N=219,974$).
  - **Val Metrics:** Model A (`0.9968`) vs Model B (`0.9963`) vs Model C (`0.9961`).
  - **Note:** The difference between Model A, Model B, and Model C on Validation is merely **0.0005 to 0.0007** (within random noise margin). Model A was selected strictly by adherence to the pre-registered decision rule.
- **Retractions and Corrections:**
  1. *Preprocessing Equivalence Retraction:* The earlier claim that "benign medians are identical at 1.00x–1.05x, proving preprocessing is identical" is **explicitly retracted**. That claim was an artifact of `StandardScaler` scale compression ($\sigma \approx 37.8\text{ seconds}$). In physical units, benign Flow Duration median in 2017 is $61,227\ \mu s$ vs $36,648\ \mu s$ in 2018 (a 1.67x physical gap).
  2. *Root Cause Attributions:* Replaced "Real Root Cause" with "Likely Causes" (السبب المرجح). Removed unsupported hypotheses regarding "AWS virtual switches".
  3. *GoldenEye & Absent Tools:* The model is not blind to GoldenEye. Out of 10,228 unseen GoldenEye flows, it detected **5,077 (49.64%)**. Total absent tool detection is **5,091 / 10,260 (49.62%)**.
  4. *Anomaly Layer Infiltration:* The claim of 100% Infiltration zero-day detection was retracted. Under `AnomalyPreprocessor`, the actual detection rate is **6.89%** (689 / 10,000).

---

## 2. Item 1: Contradiction in Benign Flow Duration Medians

### (a) Scale Compression vs Physical Units
The contradiction between the earlier z-score median table (-0.5307 vs -0.5313) and physical units ($61,227\ \mu s$ vs $36,648\ \mu s$) is explained by the StandardScaler variance:
- Scaler Mean ($\mu$): $20,130,166.76\ \mu s$ (~20.13 seconds).
- Scaler Scale ($\sigma$): $37,818,725.02\ \mu s$ (~37.82 seconds) driven by massive 120-second outlier flows.
- Z-score Calculation:
  $$\text{Z}_{2017} = \frac{61,226.8 - 20,130,166.8}{37,818,725.0} = -0.530661$$
  $$\text{Z}_{2018} = \frac{36,648.4 - 20,130,166.8}{37,818,725.0} = -0.531311$$
- Difference in Z-score space: $|-0.530661 - (-0.531311)| = \mathbf{0.000650}$.
- **Retraction:** Reporting benign medians in z-score space masked a real physical divergence ($61.2\text{ ms}$ vs $36.6\text{ ms}$). The claim that "preprocessing is identical and therefore domain shift is purely attack-related" was invalid.

---

## 3. Item 2: Likely Root Causes of 2018 Domain Shift

### (a) Adversarial Validation Feature Importance & Ablation
A classifier (XGBoost, 100 trees) distinguishes 2017 Benign from 2018 Benign with **ROC-AUC = 1.0000 (±0.0000)**.
- **Top 5 Features:**
  1. `URG Flag Count`: importance = `0.7722`
  2. `PSH Flag Count`: importance = `0.1861`
  3. `Subflow Bwd Bytes`: importance = `0.0260`
  4. `Packet Length Min`: importance = `0.0113`
  5. `Flow IAT Std`: importance = `0.0017`
- **Ablation Study (AUC after removing top features):**
  - Drop Top 1 feature (68 features left): **ROC-AUC = 1.0000**
  - Drop Top 3 features (66 features left): **ROC-AUC = 1.0000**
  - Drop Top 5 features (64 features left): **ROC-AUC = 1.0000**
  - Drop Top 10 features (59 features left): **ROC-AUC = 1.0000**
  - Drop Top 15 features (54 features left): **ROC-AUC = 1.0000**
  - Drop Top 20 features (49 features left): **ROC-AUC = 1.0000**
*Finding:* The separation between 2017 and 2018 is pervasive across almost all features, not caused by a single shortcut feature.

### (b) Sentinel Value Investigation
- **`Flow IAT Min < 0` in 2017:**
  - Benign Train flows: **1,782 / 1,304,402 (0.14%)**.
  - All Train flows: **1,926 / 1,539,838 (0.13%)**.
  - Minimum observed value: **`-14.0` $\mu s$**.
  - 2018 Benign flows: **0 / 60,000 (0.00%)**.
  - *Origin:* Extractor negative timestamp bug in CICFlowMeter v1 when out-of-order packets arrive.
- **`Fwd IAT Std == -0.5` in 2018:**
  - Found in 0 flows (0.00%). The earlier printed value of -0.5 was an indexing lookup typo on a derived array.

### (c) Provenance, Extractor & Sampling Specifications
- **2017 Dataset Source:** `data/raw/*-no-metadata.parquet` (Community conversion from UNB CIC-IDS2017 CSVs via pyarrow 8.0.0, pandas 1.3.5). Features originally generated using UNB's original Java extractor (`CICFlowMeter v1`). Environment: Physical lab network at UNB (B-Building).
- **2018 Dataset Source:** CSE-CIC-IDS2018 CSVs, extracted using `CICFlowMeter-V3`. Environment: Amazon Web Services (AWS) cloud infrastructure (500 VMs, 50 target subnets).
- **2018 Sampling Specification:** Uniform random sampling over all files, `seed = 42`, capped at `10,000` per original raw attack label and `60,000` total Benign flows ($N=162,658$).
- **Split for 1(b):** Stratified random split (`train_test_split(test_size=0.30, random_state=42, stratify=y)`).
- **Likely Root Causes (السبب المرجح):**
  1. Extractor logic drift between CICFlowMeter v1 (2017) and v3 (2018) in calculating subflows and negative inter-arrival times.
  2. Cloud virtualization vs physical lab topologies (packet timing, NAT aggregation, MTU).

### (d) Raw-Unit Quantiles for Top 15 Features (Benign Traffic)
| Feature | 2017 Benign [p1, p50, p99] (Raw Units) | 2018 Benign [p1, p50, p99] (Raw Units) |
| :--- | :--- | :--- |
| **Flow Duration** | [3.0 $\mu s$, 61,226.8 $\mu s$, 113,767,820.0 $\mu s$] | [1.0 $\mu s$, 36,648.4 $\mu s$, 115,221,691.0 $\mu s$] |
| **Flow Packets/s** | [0.03, 20.94, 666,666.67] | [0.03, 105.90, 2,000,000.00] |
| **Flow Bytes/s** | [0.0, 83.1, 8,000,000.0] | [0.0, 153.2, 10,000,000.0] |
| **Total Fwd Packets** | [1.0, 2.0, 48.0] | [1.0, 2.0, 41.0] |
| **Total Backward Packets** | [0.0, 2.0, 56.0] | [0.0, 1.0, 39.0] |
| **Packet Length Mean** | [0.0, 68.0, 1,234.5] | [0.0, 44.0, 1,180.2] |
| **Fwd Packet Length Max** | [0.0, 46.0, 1,460.0] | [0.0, 31.0, 1,460.0] |
| **Bwd Packet Length Max** | [0.0, 97.0, 4,380.0] | [0.0, 64.0, 3,892.0] |
| **Init Fwd Win Bytes** | [-1.0, 29,200.0, 65,535.0] | [-1.0, 26,883.0, 65,535.0] |
| **Init Bwd Win Bytes** | [-1.0, 235.0, 65,535.0] | [-1.0, 219.0, 65,535.0] |
| **Flow IAT Mean** | [0.5 $\mu s$, 14,321.0 $\mu s$, 28,095,946.0 $\mu s$] | [0.5 $\mu s$, 11,210.0 $\mu s$, 24,984,812.0 $\mu s$] |
| **Flow IAT Min** | [-14.0 $\mu s$, 3.0 $\mu s$, 28,095,946.0 $\mu s$] | [0.0 $\mu s$, 2.0 $\mu s$, 24,984,812.0 $\mu s$] |
| **Fwd IAT Min** | [0.0 $\mu s$, 3.0 $\mu s$, 48,010,483.5 $\mu s$] | [0.0 $\mu s$, 1.0 $\mu s$, 38,206,128.5 $\mu s$] |
| **Bwd IAT Min** | [0.0 $\mu s$, 3.0 $\mu s$, 31,643,514.8 $\mu s$] | [0.0 $\mu s$, 1.0 $\mu s$, 30,554,821.2 $\mu s$] |
| **Avg Bwd Segment Size** | [0.0, 48.5, 1,024.0] | [0.0, 32.0, 980.0] |

---

## 4. Item 3: Raw Label Distribution & Fixed Present/Absent Table

### (a) Raw-Label Flow Counts Across Splits (Train / Val / Test)
| Class | Raw Flow Label | Train (70%) | Val (10%) | Test (10%) | Total Clean Flows |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **BENIGN** | `Benign` | 1,304,402 | 186,343 | 186,344 | 1,863,432 |
| **Bot** | `Bot` | 1,003 | 143 | 144 | 1,434 |
| **BruteForce** | `FTP-Patator` | 5,931 | 0 | 0 | 5,931 |
| **BruteForce** | `SSH-Patator` | 474 | 915 | 915 | 3,219 |
| **DDoS** | `DDoS` | 89,609 | 12,802 | 12,802 | 128,013 |
| **DoS** | `DoS GoldenEye` | 0 | 0 | 10,228 | 10,286 |
| **DoS** | `DoS Hulk` | 124,975 | 19,370 | 9,131 | 172,788 |
| **DoS** | `DoS Slowhttptest` | 5,228 | 0 | 0 | 5,228 |
| **DoS** | `DoS slowloris` | 5,385 | 0 | 0 | 5,385 |
| **DoS** | `Heartbleed` | 0 | 0 | 11 | 11 |
| **Infiltration** | `Infiltration` | 36 | 0 | 0 | 36 |
| **PortScan** | `PortScan` | 1,295 | 185 | 185 | 1,850 |
| **WebAttack** | `Web Attack - Brute Force` | 1,470 | 0 | 0 | 1,470 |
| **WebAttack** | `Web Attack - Sql Injection` | 0 | 0 | 21 | 21 |
| **WebAttack** | `Web Attack - XSS` | 30 | 214 | 194 | 652 |

### (b) Confirmation on Val Hulk = 19,370
- Total DoS flows in dataset: $N = 193,701$.
- Sequential split rule: Val = $\text{int}(0.10 \times 193,701) = \mathbf{19,370}$; Test = $\text{int}(0.10 \times 193,701) = \mathbf{19,370}$.
- In Val, 100% of the DoS flows are `DoS Hulk` (19,370).
- In Test, the DoS flows are `DoS Hulk` (9,131) + `DoS GoldenEye` (10,228) + `Heartbleed` (11) = **19,370**.
- **Conclusion:** Val Hulk = 19,370 is **not a copy-paste error**, but a mathematical artifact of the 10% sequential block split on 193,701 flows.

### (c) Fixed Present vs Absent Attack Recall
SQL Injection ($N=21$, 4 detected) was absent from Train and is correctly counted under Absent:

| Tool Partition | Raw Attack Tools Included | Test Samples | Detected Flows | Detection Rate (Recall) |
| :--- | :--- | :--- | :--- | :--- |
| **Present in Train** | `DoS Hulk`, `DDoS LOIC`, `SSH-Patator`, `Botnet`, `Web-XSS`, `PortScan` | 23,371 | 22,008 | **94.17%** |
| **Absent in Train** | `DoS GoldenEye` (10,228), `Heartbleed` (11), `Web-SQLi` (21) | 10,260 | 5,091 | **49.62%** |
| **Combined Total** | All Attack Tools | 33,631 | 27,099 | **80.58%** |

---

## 5. Item 4: Rigorous Bayes Prior Table & Operating Point

Isotonic regression produces a **19-step discrete step function** on validation scores. Any threshold $t$ between two adjacent steps produces identical binary classifications. Consequently, the operating point on the Test block is **effectively one single point**:

| Prevalence ($\pi_{real}$) | Operating Threshold ($t$) | Test Recall | Test FPR | True Bayes Precision | False Alarms / 1M Flows |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0.10% (1 in 1,000)** | 0.001001 | 80.58% | **0.1154%** | **41.14%** | 1,153 |
| **0.50% (1 in 200)** | 0.002002 | 80.60% | **0.1165%** | **77.67%** | 1,159 |
| **1.00% (1 in 100)** | 0.004004 | 80.60% | **0.1165%** | **87.49%** | 1,153 |
| **5.00% (1 in 20)** | 0.019019 | 80.60% | **0.1165%** | **97.33%** | 1,106 |
| **10.00% (1 in 10)** | 0.039039 | 80.60% | **0.1165%** | **98.72%** | 1,048 |

*Operational Truth:* Across $\pi_{real} \ge 0.5\%$, the model operates at **Recall = 80.60%** and **FPR = 0.1165%**. The apparent 5-threshold sweep collapses to one operating plateau due to isotonic calibration.

---

## 6. Item 5: Anomaly Control from RAW Data & Discrepancy Reconciliation

### (a) Control from Raw Held-out 2017 Benign Flows
Evaluating 186,344 raw held-out 2017 Test Benign flows directly through `AnomalyPreprocessor` (`fill_median -> signed_log1p -> clip -> StandardScaler`):
- Transformed value range: $\min = -2.7739$, $\text{median} = -0.2674$, $\max = 6.8315$.
- Operational threshold: **`0.987161`**.
- False Positives: **2,869 flows**.
- **Benign FPR on Raw 2017 Flows:** **`1.540%`** (Autoencoder alone: `1.473%`, Isolation Forest alone: `1.581%`).
- **Status:** **PASSED**. The AnomalyPreprocessor correctly reproduces ~1.54% FPR on raw held-out university benign traffic without saturation.

### (b) Exact Reconciliation of Historic FPR Numbers
- **`1.646% / 0.374%`:** Computed on 2026-11-23 (Commit `e42e18f`) on an un-gapped validation split ($N=45,000$ flows) prior to implementing near-deduplication.
- **`1.623% / 0.378%`:** Computed on 2026-11-24 on `val.npz` ($N=44,970$ flows: 19,960 CIC-IDS2017 + 25,010 UNSW-NB15) with dual buffer gaps.
- **`1.540%`:** Computed on 2026-11-24 on the 186,344 raw held-out Test benign flows.
- **2018 Benign Transfer:** **`5.96%`** (3,578 / 60,000) reflects real domain shift between UNB physical lab traffic and AWS cloud background traffic.

---

## 7. Item 6: Process Governance & Test Evaluation History

### (a) Log of Test Block Evaluations
| Eval # | Timestamp | Purpose | Observed Test Recall |
| :--- | :--- | :--- | :--- |
| **1** | 2026-11-23 02:45 | Initial benchmark on uncleaned 2017 test partition | 81.20% |
| **2** | 2026-11-24 00:51 | Clean benchmark test run after sequential block split | 80.58% |
| **3** | 2026-11-24 14:30 | Cross-dataset diagnostic on 2017 and 2018 test sets | 80.58% / 5.52% |
| **4** | 2026-11-24 16:08 | Priority audit check on Hulk drop and DoS raw labels | 80.58% |
| **5** | 2026-11-24 19:11 | Verification of rewritten `evaluate_cross_dataset.py` | 80.58% |

### (b) Model Selection Rule
- **Rule:** Selected strictly on **Validation Macro-F1** on 2026-11-24.
- **Val Macro-F1:** Model A = `0.9968`, Model B = `0.9963`, Model C = `0.9961`.
- **Finding:** The difference on Val is $\le 0.0007$. Model A was selected strictly by adherence to the pre-registered decision rule. The Test set was declared burned.
