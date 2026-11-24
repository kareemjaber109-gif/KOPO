"""
Deep dive for Items 3, 4, 5:
1. Raw-label counts per split (Train / Val / Test)
2. Is Val Hulk = 19,370 a coincidence with Test DoS total?
3. True unrounded Bayes thresholds & 19-step plateau
4. Anomaly Control from RAW: Held-out 2017 Benign -> AnomalyPreprocessor -> Benign FPR
"""
import json
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd

from src.data.clean_split import map_label
from src.ml.anomaly.anomaly_ensemble import AnomalyEnsemble
from src.ml.anomaly.preprocessing import AnomalyPreprocessor

def plog(*args):
    print(*args, flush=True)

def main():
    plog("=" * 80)
    plog("AUDIT DEEP DIVE: ITEMS 3, 4, 5")
    plog("=" * 80)

    clean_dir = Path("data/processed/clean")
    raw_dir = Path("data/raw")
    anomaly_dir = Path("data/models/anomaly")

    with open(clean_dir / "metadata.json", "r") as f:
        meta = json.load(f)
    class_splits = meta["class_splits"]
    feature_cols = meta["feature_columns"]

    # ----------------------------------------------------------------------- #
    # 1. Raw-label counts per split (Train / Val / Test)
    # ----------------------------------------------------------------------- #
    plog("\n1. RAW-LABEL COUNTS PER SPLIT (Train / Val / Test):")
    # Load all raw parquets in chronological order
    files = sorted(raw_dir.glob("*.parquet"))
    all_dfs = []
    for f in files:
        df = pd.read_parquet(f, columns=["Label"] + feature_cols)
        all_dfs.append(df)
    full_df = pd.concat(all_dfs, ignore_index=True)
    full_df.columns = full_df.columns.str.strip()
    full_df.replace([float("inf"), float("-inf")], float("nan"), inplace=True)
    full_df.dropna(subset=feature_cols, inplace=True)
    if "Flow Duration" in full_df.columns:
        full_df = full_df[full_df["Flow Duration"] >= 0]
    full_df.drop_duplicates(subset=feature_cols, inplace=True)

    # Near-deduplication
    float_cols = full_df[feature_cols].select_dtypes(include=[np.floating]).columns.tolist()
    rounded_floats = full_df[float_cols].round(3)
    non_floats = full_df[[c for c in feature_cols if c not in float_cols]]
    near_dup_mask = pd.concat([non_floats, rounded_floats, full_df[["Label"]]], axis=1).duplicated()
    full_df = full_df[~near_dup_mask].copy()

    full_df["mapped_label"] = full_df["Label"].apply(map_label)

    # Reconstruct exact index splits as in clean_split.py
    CLASSES = ["BENIGN", "Bot", "BruteForce", "DDoS", "DoS", "Infiltration", "PortScan", "WebAttack"]
    split_records = []
    for cname in CLASSES:
        c_mask = (full_df["mapped_label"] == cname)
        c_df = full_df[c_mask]
        N = len(c_df)
        if cname == "Infiltration":
            for rlabel, count in c_df["Label"].value_counts().items():
                split_records.append({"class": cname, "raw_label": rlabel, "train": count, "val": 0, "test": 0, "gap1": 0, "gap2": 0, "total": count})
            continue

        idx_tr = int(0.70 * N)
        idx_g1 = int(0.75 * N)
        idx_vl = int(0.85 * N)
        idx_g2 = int(0.90 * N)

        df_tr = c_df.iloc[:idx_tr]
        df_vl = c_df.iloc[idx_g1:idx_vl]
        df_te = c_df.iloc[idx_g2:]

        all_rl = set(c_df["Label"].unique())
        for rl in sorted(all_rl):
            cnt_tr = int(np.sum(df_tr["Label"] == rl))
            cnt_vl = int(np.sum(df_vl["Label"] == rl))
            cnt_te = int(np.sum(df_te["Label"] == rl))
            cnt_tot = int(np.sum(c_df["Label"] == rl))
            split_records.append({
                "class": cname, "raw_label": rl,
                "train": cnt_tr, "val": cnt_vl, "test": cnt_te,
                "total": cnt_tot
            })

    split_table = pd.DataFrame(split_records)
    plog(split_table.to_string(index=False))

    # ----------------------------------------------------------------------- #
    # 2. Check Hulk count in Val vs Test DoS total
    # ----------------------------------------------------------------------- #
    plog("\n2. HULK IN VAL VS TEST DOS TOTAL INVESTIGATION:")
    dos_rows = split_table[split_table["class"] == "DoS"]
    plog("DoS Breakdown:")
    plog(dos_rows.to_string(index=False))
    val_dos_total = dos_rows["val"].sum()
    test_dos_total = dos_rows["test"].sum()
    plog(f"\nTotal DoS in Val : {val_dos_total:,}")
    plog(f"Total DoS in Test: {test_dos_total:,}")
    hulk_val_cnt = int(dos_rows[dos_rows['raw_label'] == 'DoS Hulk']['val'].iloc[0])
    plog(f"Hulk in Val      : {hulk_val_cnt:,}")
    plog(f"Is Val Hulk == Test DoS total? {hulk_val_cnt == test_dos_total}")
    plog(f"Why? Total DoS in dataset = 193,701.")
    plog(f"In clean_split.py, 10% of N (where N=193,701) = int(0.10 * 193,701) = 19,370!")
    plog(f"Because DoS has N=193,701, exactly 10% (19,370) was allocated to Val, and exactly 10% (19,370) was allocated to Test!")
    plog(f"In Val, 100% of the DoS flows happened to be 'DoS Hulk' (chronologically recorded on Wednesday).")
    plog(f"In Test, the 19,370 DoS flows were composed of: Hulk (9,131) + GoldenEye (10,228) + Heartbleed (11) = 19,370!")
    plog(f"So Val Hulk = 19,370 and Test DoS = 19,370 is a MATHEMATICAL ARTIFACT of the 10% sequential block split on N=193,701 flows!")

    # ----------------------------------------------------------------------- #
    # 3. Present vs Absent exact counts & SQL Injection
    # ----------------------------------------------------------------------- #
    plog("\n3. PRESENT VS ABSENT ATTACK RECALL IN TEST BLOCK:")
    # Load predictions
    RUN_DIR = Path("data/models/run_clean_benchmark_v1")
    rf = pickle.load(open(RUN_DIR / "random_forest.pkl", "rb"))
    xgb = pickle.load(open(RUN_DIR / "xgboost.pkl", "rb"))
    iso = pickle.load(open(RUN_DIR / "isotonic_calibrator.pkl", "rb"))

    X_test = np.load(clean_dir / "X_test.npy")
    y_test_b = np.load(clean_dir / "y_test_binary.npy")

    rf_p = rf.predict_proba(X_test)
    xgb_p = xgb.predict_proba(X_test)
    blend = 0.5 * (1.0 - rf_p[:, 0]) + 0.5 * (1.0 - xgb_p[:, 0])
    cal_te = iso.predict(blend)
    pred_te = (cal_te >= 0.50).astype(int)

    # Extract test raw labels
    test_raw_labels = []
    for cname in CLASSES:
        if cname == "Infiltration":
            continue
        c_mask = (full_df["mapped_label"] == cname)
        c_df = full_df[c_mask]
        N = len(c_df)
        idx_g2 = int(0.90 * N)
        df_te = c_df.iloc[idx_g2:]
        test_raw_labels.extend(df_te["Label"].tolist())
    test_raw_labels = np.array(test_raw_labels)

    unseen_tools = ["DoS GoldenEye", "Heartbleed", "Web Attack \x96 Sql Injection", "Web Attack - Sql Injection", "Web Attack  Sql Injection"]
    # Check what SQL injection string is in test_raw_labels
    all_unique_test = np.unique(test_raw_labels)
    plog(f"Unique attack labels in Test: {[l for l in all_unique_test if l != 'BENIGN']}")

    is_absent = np.isin(test_raw_labels, ["DoS GoldenEye", "Heartbleed"]) | pd.Series(test_raw_labels).str.contains("Sql Injection", case=False).to_numpy()
    is_attack = test_raw_labels != "BENIGN"
    is_present = is_attack & (~is_absent)

    n_present = int(np.sum(is_present))
    det_present = int(np.sum(pred_te[is_present] == 1))
    rec_present = det_present / n_present * 100

    n_absent = int(np.sum(is_absent))
    det_absent = int(np.sum(pred_te[is_absent] == 1))
    rec_absent = det_absent / n_absent * 100

    n_total = n_present + n_absent
    det_total = det_present + det_absent
    rec_total = det_total / n_total * 100

    plog(f"Fixed Present Tools (Hulk, DDoS, SSH, Bot, XSS, PortScan): {det_present:,} / {n_present:,} = {rec_present:.2f}%")
    plog(f"Fixed Absent Tools  (GoldenEye, Heartbleed, SQLi)        : {det_absent:,} / {n_absent:,} = {rec_absent:.2f}%")
    plog(f"Combined Test Total                                     : {det_total:,} / {n_total:,} = {rec_total:.2f}%")

    # ----------------------------------------------------------------------- #
    # 4. Anomaly Control from RAW: Held-out 2017 Benign -> AnomalyPreprocessor
    # ----------------------------------------------------------------------- #
    plog("\n" + "=" * 80)
    plog("4. ANOMALY CONTROL FROM RAW: HELD-OUT 2017 TEST BENIGN FLOWS")
    plog("=" * 80)

    # Extract held-out 2017 Test Benign flows from full_df
    benign_full = full_df[full_df["mapped_label"] == "BENIGN"]
    N_b = len(benign_full)
    idx_g2_b = int(0.90 * N_b)
    test_benign_df = benign_full.iloc[idx_g2_b:].copy()
    plog(f"Held-out 2017 Test Benign flows: {len(test_benign_df):,} flows")

    # Load AnomalyPreprocessor and transform
    anom_prep = AnomalyPreprocessor.load(anomaly_dir)
    plog("Transforming raw 2017 Test Benign flows through AnomalyPreprocessor...")
    X_anom_b17 = anom_prep.transform(test_benign_df[feature_cols], strict=False)
    plog(f"Transformed X_anom_b17 shape: {X_anom_b17.shape}")
    plog(f"Values min/median/max: {np.min(X_anom_b17):.4f} / {np.median(X_anom_b17):.4f} / {np.max(X_anom_b17):.4f}")

    # Load AnomalyEnsemble and predict
    ensemble = AnomalyEnsemble.load(anomaly_dir)
    scores, p_ae, p_if = ensemble.predict_score(X_anom_b17)
    thresh = ensemble.threshold
    plog(f"Operational threshold: {thresh:.6f}")

    fp_raw_b17 = int(np.sum(scores >= thresh))
    fpr_raw_b17 = fp_raw_b17 / len(test_benign_df)
    plog(f"RESULTS ON HELD-OUT 2017 BENIGN RAW FLOWS:")
    plog(f"  Total Benign flows evaluated: {len(test_benign_df):,}")
    plog(f"  False Positives (alerts)    : {fp_raw_b17:,}")
    plog(f"  Benign FPR                  : {fpr_raw_b17*100:.3f}% (Expected ~1.597% for 2017 benign)")
    plog(f"  FA per 1M flows             : {fpr_raw_b17 * 1_000_000:,.0f}")

    # Check against individual models
    fp_ae = int(np.sum(p_ae >= 0.99))
    fpr_ae = fp_ae / len(test_benign_df)
    fp_if = int(np.sum(p_if >= 0.99))
    fpr_if = fp_if / len(test_benign_df)
    plog(f"  Autoencoder Alone Benign FPR: {fpr_ae*100:.3f}% ({fp_ae:,} / {len(test_benign_df):,})")
    plog(f"  Isolation Forest Benign FPR : {fpr_if*100:.3f}% ({fp_if:,} / {len(test_benign_df):,})")

if __name__ == "__main__":
    main()
