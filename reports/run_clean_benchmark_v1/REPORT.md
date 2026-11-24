# KOPO ThreatNet: Phase 1 Research Baseline Report & Audit Findings
**Run ID:** `run_clean_benchmark_v1`  
**Date:** 2026-11-24  
**Status:** `RESEARCH BASELINE (NOT CERTIFIED - NO PHASE 2)`  
**Model Origin:** `REAL` (Trained strictly on CIC-IDS2017 Train Block)  
**External Hold-out Validation:** `CSE-CIC-IDS2018` (162,658 sampled flows) & `UNSW-NB15`  

---

## 1. Executive Summary & Review Alignment

- **Certification Status:** Held strictly as a **Research Baseline (`certified: false`)**. Phase 2 (Alert aggregation, incident DB, backend API) remains **blocked** and will not proceed without explicit user sign-off.
- **Test Set Governance & Burn Notice:** The held-out sequential Test block (219,975 flows) was touched approximately four times during this session for baseline evaluation, threshold verification, and root-cause diagnostics. Consequently, the Test block is officially designated as **burned for hyperparameter selection**. Model A was selected strictly based on **Validation split performance (Val Macro-F1 = 0.9968)**.
- **Clarification on Macro-F1:**
  - **In-Distribution Test Macro-F1:** `0.9357` (evaluated strictly over the 7 classes present in the Test block; Infiltration has $N=0$ in Test and was excluded).
  - **Validation Macro-F1:** Model A (`0.9968`) vs Model B (`0.9963`) vs Model C (`0.9961`).
- **Retraction and Correction of False Claims:**
  1. *GoldenEye Detection:* The previous claim of "total blindness to GoldenEye" was mathematically disproven. Out of 10,228 unseen GoldenEye flows in the Test block, the model detected **5,077 flows (49.64% recall)**. Along with Hulk (87.45%) and Heartbleed (90.91%), total DoS recall reached 13,072 / 19,370 (67.49%), demonstrating genuine partial zero-day generalization.
  2. *Anomaly Layer Infiltration Claim:* The claim that the anomaly ensemble detects 100% of zero-day Infiltration has been **completely retracted**. That claim was an artifact of an unscaled evaluation script. Under the correct normalized pipeline (`AnomalyPreprocessor`), the actual zero-day detection rate for Infiltration on 2018 is **6.89%** (689 / 10,000).
  3. *Model C Shortcut Learning Claim:* The claim that Model C eliminated shortcut learning was retracted. Dropping backward-direction features increased 2018 recall marginally from 5.52% to 9.16%, but exploded the False Positive Rate by **24×** (0.08% to 1.98%) and reduced precision from 99.1% to 88.8%.

---

## 2. Item 1: CSE-CIC-IDS2018 Root Cause Analysis

### (a) Adversarial Validation: 2017 vs 2018 Separation
To test whether 2017 and 2018 distributions can be distinguished, a binary classifier (XGBoost, 100 trees, 3-fold stratified CV) was trained to discriminate between 2017 and 2018 flows using the 69 behavioral features:

| Traffic Subset | N (2017) | N (2018) | Adversarial ROC-AUC | Separation Status |
| :--- | :--- | :--- | :--- | :--- |
| **Benign vs Benign** | 15,000 | 15,000 | **1.0000 (±0.0000)** | Completely Separable |
| **DDoS vs DDoS** | 15,000 | 15,000 | **1.0000 (±0.0000)** | Completely Separable |
| **DoS vs DoS** | 15,000 | 15,000 | **1.0000 (±0.0000)** | Completely Separable |
| **BruteForce vs BruteForce** | 6,405 | 15,000 | **1.0000 (±0.0000)** | Completely Separable |

*Conclusion:* Across every traffic class, 2017 and 2018 are 100% separable. A simple tree classifier distinguishes the two datasets with zero error.

### (b) Learnability & Bi-Directional Transfer
To determine if 2018 is inherently unlearnable or corrupted, an XGBoost classifier was trained on a 70% split of 2018 flows (113,860 flows) and evaluated both in-distribution on 2018 held-out test (48,798 flows) and out-of-distribution on the 2017 Test block:

1. **2018-Trained Model Evaluated on 2018 Held-Out Test (In-Distribution):**
   - **Attack Recall:** **`93.14%`** | **Benign FPR:** **`1.233%`** | **Binary F1:** **`0.9609`**
   - *Per-Class Recall:* Bot: `99.87%` | BruteForce: `100.00%` | DDoS: `99.98%` | DoS: `99.89%` | WebAttack: `96.06%` | Infiltration: `30.57%`.
   - *Finding:* CSE-CIC-IDS2018 is **highly learnable on its own**. The features are not random noise.
2. **Reverse Cross-Dataset Transfer (2018-Trained Model on 2017 Test Block):**
   - **Attack Recall:** **`53.88%`** | **Benign FPR:** **`28.977%`** | **Binary F1:** **`0.3427`**
   - *Finding:* The cross-dataset barrier is **bi-directional**. Training on 2018 causes a 28.98% false alarm rate on 2017 benign flows.

### (c) Raw-Unit Quantiles for Benign Flows (p1, p50, p99)
Comparing benign physical traffic parameters reveals physical environment and extractor divergences:

| Feature Name | 2017 Benign [p1, p50, p99] (Raw Units) | 2018 Benign [p1, p50, p99] (Raw Units) | Physical Interpretation |
| :--- | :--- | :--- | :--- |
| **Flow Duration** | [3.0 $\mu s$, 302,377.0 $\mu s$, 113,767,820.0 $\mu s$] | [1.0 $\mu s$, 36,077.0 $\mu s$, 115,221,691.0 $\mu s$] | AWS flows terminate ~10× faster at median |
| **Flow Packets/s** | [0.03, 20.94, 666,666.67] | [0.03, 105.90, 2,000,000.00] | AWS packet rate median is 5× higher |
| **Fwd IAT Std** | [0.0, 7,581.2, 38,157,639.1] | [0.0, -0.5, 41,751,213.3] | CICFlowMeter-V3 flag artifact (-0.5) |
| **Flow IAT Min** | [-12.0, 3.0, 28,095,946.0] | [0.0, 2.0, 24,984,812.0] | Extractor negative timestamp artifact in 2017 |
| **Fwd IAT Min** | [0.0, 3.0, 48,010,483.5] | [0.0, 1.0, 38,206,128.5] | AWS network virtualization latency lower |
| **Bwd IAT Min** | [0.0, 3.0, 31,643,514.8] | [0.0, 1.0, 30,554,821.2] | AWS virtual switch ACK turnaround faster |

### (d) Provenance & Extractor Audit
- **UNB CIC-IDS2017:** Captured on an on-premises physical laboratory network (UNB B-Building). Flow features generated with **CICFlowMeter v1 (Java)**.
- **CSE-CIC-IDS2018:** Captured on **Amazon Web Services (AWS)** across 500 virtual machines and 50 target subnets. Flow features generated with **CICFlowMeter-V3**.
- **Attack Tool Verification:**
  - *DoS:* Hulk, GoldenEye, Slowloris, Slowhttptest were used in **both 2017 and 2018**.
  - *BruteForce:* Patator (FTP/SSH) was used in **both 2017 and 2018**.
- **Real Root Cause:** The failure of 2017-trained models on 2018 is not caused by different attack tools or preprocessing bugs. It is driven by:
  1. **Extractor Behavioral Drift:** CICFlowMeter v1 vs CICFlowMeter-V3 calculate flow expiration, subflows, and negative IAT values differently.
  2. **Cloud vs Physical Network Topologies:** AWS EC2 virtualized networking, multi-tenant NAT, virtual MTU, and TCP ACK aggregation fundamentally change flow timing and window metrics.

---

## 3. Item 2: Seen vs Unseen Attack Recall Split (2017 Test Block)

### (a) Exact Hulk Recall: Validation vs Test Degradation
The exact same attack tool (`DoS Hulk`) was evaluated across the sequential splits:
- **Hulk in Validation Block:** **19,367 / 19,370 detected $\rightarrow$ `99.98%` recall** (only 3 flows missed).
- **Hulk in Test Block:** **7,985 / 9,131 detected $\rightarrow$ `87.45%` recall** (1,146 flows missed).
- **Hulk Performance Drop:** **`-12.54%`** drop on the exact same tool.
- *Insight:* Even for an identical attack tool, validation block performance is inherently optimistic and does not fully predict held-out sequential block performance.

### (b) Partitioning by Tool Presence in Training Data
Evaluating the 33,631 attack flows in the 2017 Test block by tool availability in the Train block:

| Tool Partition | Raw Attack Tools Included | Test Samples | Detected Flows | Detection Rate (Recall) |
| :--- | :--- | :--- | :--- | :--- |
| **Present in Train** | `DoS Hulk`, `DDoS LOIC`, `SSH-Patator`, `Botnet`, `Web-XSS`, `PortScan` | 23,392 | 22,012 | **94.10%** |
| **Absent in Train** | `DoS GoldenEye` (10,228), `Heartbleed` (11), `Web-SQLi` (21) | 10,239 | 5,087 | **49.68%** |
| **Combined Total** | All Attack Tools | 33,631 | 27,099 | **80.58%** |

*Breakdown of Absent Tools:*
- `DoS GoldenEye`: 5,077 / 10,228 detected (**`49.64%` recall**).
- `Heartbleed`: 10 / 11 detected (**`90.91%` recall**).
- `Web Attack - SQL Injection`: 4 / 21 detected (**`19.05%` recall**).

---

## 4. Item 3: Rigorous Bayes Prior Adjustment Table

In operational deployment, network flow base rates $\pi_{real}$ are heavily dominated by benign traffic. Bayes' theorem governs operational precision:

$$\text{Precision}_{Bayes} = \frac{\text{Recall} \cdot \pi_{real}}{\text{Recall} \cdot \pi_{real} + \text{FPR} \cdot (1 - \pi_{real})}$$

Isotonic regression produces 19 discrete steps on validation flows (`min = 0.0000`, `p50 = 0.0000`, `p90 = 1.0000`, lowest non-zero step = `0.000083`). The operating threshold $t$ selected on Validation was applied to the Test block:

| Prevalence ($\pi_{real}$) | Operating Threshold ($t$) | Test Recall | Test FPR | True Bayes Precision | False Alarms / 1M Flows |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0.10% (1 in 1,000)** | 0.001000 | 80.58% | **0.1154%** | **41.14%** | 1,153 |
| **0.50% (1 in 200)** | 0.002000 | 80.60% | **0.1165%** | **77.67%** | 1,159 |
| **1.00% (1 in 100)** | 0.004000 | 80.60% | **0.1165%** | **87.49%** | 1,153 |
| **5.00% (1 in 20)** | 0.019000 | 80.60% | **0.1165%** | **97.33%** | 1,106 |
| **10.00% (1 in 10)** | 0.039000 | 80.60% | **0.1165%** | **98.72%** | 1,048 |

*Audit Notes:*
1. The `0.01%` row from prior drafts was discarded because 5 false alarms per million is statistical noise at sample size $N=186k$.
2. The threshold `0.0100` was previously reported because it was the floor of the numerical grid search; unrounded values in continuous probability space are shown above.
3. At 1% attack prevalence, the model produces **87.49% true precision** with **1,153 false alarms per million flows**.

---

## 5. Item 4: Anomaly Layer Quantitative Evaluation on Raw 2018 Flows

The dual Anomaly Ensemble (Autoencoder + Isolation Forest) was evaluated on the 162,658 flows of CSE-CIC-IDS2018 using the verified `AnomalyPreprocessor` (`fill_median -> signed_log1p -> clip -> StandardScaler`):
- Feature value range: $\min = -2.7739$, $\text{median} = -0.3840$, $\max = 6.8315$ (zero saturation).
- Operational Threshold: **`0.9872`** (calibrated at the 99th percentile of Benign Validation flows).

### (a) Model Component Performance on 2018
| Component | Threshold | Benign FPR | FA / 1M Flows | Attack Recall (95% Wilson CI) |
| :--- | :--- | :--- | :--- | :--- |
| **Dual Anomaly Ensemble** | **0.9872** | **5.96%** (CI 5.8%–6.2%) | **59,633** | **16.28%** (CI 16.1%–16.5%) |
| **Autoencoder Alone** | 0.9900 | 7.39% (CI 7.2%–7.6%) | 73,917 | 18.37% (CI 18.1%–18.6%) |
| **Isolation Forest Alone** | 0.9900 | 6.05% (CI 5.9%–6.2%) | 60,533 | 16.10% (CI 15.9%–16.3%) |

### (b) Per-Category Attack Recall on 2018 (Dual Ensemble)
| Attack Category | Total Flows | Detected Flows | Recall Rate | 95% Wilson Confidence Interval |
| :--- | :--- | :--- | :--- | :--- |
| **DDoS** | 21,730 | 6,097 | **28.06%** | [27.46%, 28.66%] |
| **WebAttack** | 928 | 249 | **26.83%** | [24.08%, 29.77%] |
| **DoS** | 40,000 | 9,633 | **24.08%** | [23.67%, 24.50%] |
| **Infiltration** | 10,000 | 689 | **6.89%** | [6.41%, 7.40%] |
| **Bot** | 10,000 | 41 | **0.41%** | [0.30%, 0.56%] |
| **BruteForce** | 20,000 | 0 | **0.00%** | [0.00%, 0.02%] |

### (c) Per-Raw-Label Recall on 2018 (Dual Ensemble)
| Raw Flow Label | Total Flows | Detected Flows | Detection Rate | 95% Wilson Confidence Interval |
| :--- | :--- | :--- | :--- | :--- |
| `DDOS attack-LOIC-UDP` | 1,730 | 1,730 | **100.00%** (Recall) | [99.78%, 100.00%] |
| `DoS attacks-Slowloris` | 10,000 | 7,842 | **78.42%** (Recall) | [77.60%, 79.22%] |
| `Brute Force -XSS` | 230 | 102 | **44.35%** (Recall) | [38.07%, 50.81%] |
| `DDoS attacks-LOIC-HTTP` | 10,000 | 4,367 | **43.67%** (Recall) | [42.70%, 44.64%] |
| `Brute Force -Web` | 611 | 147 | **24.06%** (Recall) | [20.84%, 27.60%] |
| `DoS attacks-GoldenEye` | 10,000 | 1,772 | **17.72%** (Recall) | [16.98%, 18.48%] |
| `Infilteration` | 10,000 | 689 | **6.89%** (Recall) | [6.41%, 7.40%] |
| `DoS attacks-Hulk` | 10,000 | 19 | **0.19%** (Recall) | [0.12%, 0.30%] |
| `Bot` | 10,000 | 41 | **0.41%** (Recall) | [0.30%, 0.56%] |
| `SSH-Bruteforce` | 10,000 | 0 | **0.00%** (Recall) | [0.00%, 0.04%] |
| `FTP-BruteForce` | 10,000 | 0 | **0.00%** (Recall) | [0.00%, 0.04%] |
| `DDOS attack-HOIC` | 10,000 | 0 | **0.00%** (Recall) | [0.00%, 0.04%] |
| `DoS attacks-SlowHTTPTest`| 10,000 | 0 | **0.00%** (Recall) | [0.00%, 0.04%] |
| `SQL Injection` | 87 | 0 | **0.00%** (Recall) | [0.00%, 4.23%] |
| `Benign` | 60,000 | 3,578 | **5.96%** (FPR) | [5.78%, 6.16%] |

### (d) Benign FPR Discrepancy Reconciliation
1. **Calibration Split (`val.npz`, $N=44,970$):** Overall Benign FPR = **`1.001%`** (UNSW = `0.378%`, CIC-IDS2017 = `1.623%`).
2. **Test Split (`test.npz`, $N=44,968$):** Overall Benign FPR = **`0.990%`** (UNSW = `0.382%`, CIC-IDS2017 = `1.597%`).
3. **Legacy Report (1.646% / 0.374%):** Pre-clean partition without dual buffer gaps. Both confirm that university enterprise traffic (CIC-IDS2017) produces ~4× higher false alarms than synthetic lab traffic (UNSW).
4. **2018 Domain Shift:** Cross-dataset benign transfer produces **`5.96%` FPR** (59,633 FA/1M), reflecting the domain shift between UNB physical lab traffic and AWS cloud background traffic.

---

## 6. Item 5: Governance, Cleanliness & Verification Audit

| Requirement / Item | Reviewer Audit Standard | Verification Status |
| :--- | :--- | :--- |
| **Model Selection Protocol** | Date-stamped strictly from Validation metrics | **VERIFIED:** Model A selected based on Val Macro-F1 = `0.9968`. Test was never used for model selection. |
| **Test Set Integrity** | Disclose evaluation frequency and declare burned | **VERIFIED:** Test evaluated ~4 times; declared burned for hyperparameter selection. |
| **No Hardcoded Values** | `evaluate_cross_dataset.py` free of static constants | **VERIFIED:** Legacy `0.38` and `HierarchicalIDS` completely excised; loaded from `manifest.json`. |
| **Label Encoding Safety** | `map_label` must throw exception on unknown classes | **VERIFIED:** Throws `ValueError` with detailed message. Tested in `tests/test_protocol_parity.py`. |
| **Pytest Test Suite** | 100% pass on protocol parity and engine | **VERIFIED:** `22 passed in 28.35s`. |
| **Secret & Artifact Leakage**| No `.env` or temporary weights committed | **VERIFIED:** `git log --all --full-history --oneline -- .env` confirmed empty. |
| **Certification Status** | Retain research baseline flag | **VERIFIED:** `manifest.json` set to `certified: false`, `run_type: "research_baseline"`. |

---

## 7. Next Steps & Phase 2 Transition Plan
1. **Phase 1 Closure:** All six reviewer audit items are fulfilled with complete mathematical rigor and reproducible scripts.
2. **Phase 2 Entry Gate:** Transition to Phase 2 (FastAPI backend, TimescaleDB incident schema, SOC alert aggregator) will only begin upon explicit confirmation from the user.
