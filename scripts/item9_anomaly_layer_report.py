"""
Item 9: Anomaly layer quantitative report (CORRECT).
The anomaly model has its own 67-feature pipeline with its own scaler.
Need to: read raw 2018 CSVs → select the 67 features → apply anomaly scaler → score.
Instead: use the existing 2018 test data but re-select & rescale with anomaly pipeline.
"""
import json, math, pickle, joblib, numpy as np, sys, os
from pathlib import Path

sys.path.insert(0, os.getcwd())
from src.ml.anomaly.anomaly_ensemble import AnomalyEnsemble

ANOMALY_DIR = Path("data/models/anomaly")
CLEAN_DIR   = Path("data/processed/clean")
RUN_DIR     = Path("data/models/run_clean_benchmark_v1")


def wilson_ci(k, n, z=1.96):
    if n == 0: return 0.0, 0.0, 0.0
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2*n)) / denom
    margin = (z * math.sqrt(p*(1-p)/n + z**2/(4*n**2))) / denom
    return p, max(0.0, center-margin), min(1.0, center+margin)


def report_component(name, scores, threshold, y_true_binary, y_true_multi=None, class_names=None, source_name=""):
    preds = (scores >= threshold).astype(int)
    benign_mask  = (y_true_binary == 0)
    attack_mask  = (y_true_binary == 1)
    n_benign = int(np.sum(benign_mask))
    n_attack = int(np.sum(attack_mask))
    fp = int(np.sum(preds[benign_mask] == 1))
    tp = int(np.sum(preds[attack_mask] == 1))
    fpr    = fp / n_benign if n_benign > 0 else 0.0
    recall = tp / n_attack if n_attack > 0 else 0.0
    fa_per_million = fpr * 1_000_000

    print(f"\n  [{name}] on {source_name}")
    print(f"    Benign: {n_benign:,} | FP: {fp:,} | FPR: {fpr*100:.4f}% | FA/1M: {fa_per_million:,.0f}")
    print(f"    Attack: {n_attack:,} | TP: {tp:,} | Recall: {recall*100:.2f}%")

    if y_true_multi is not None and class_names is not None:
        for c_idx, cname in enumerate(class_names):
            if cname == "BENIGN": continue
            mask = (y_true_multi == c_idx)
            cnt  = int(np.sum(mask))
            if cnt == 0: continue
            det  = int(np.sum(preds[mask] == 1))
            rec  = det / cnt if cnt > 0 else 0.0
            _, lo, hi = wilson_ci(det, cnt)
            print(f"    {cname:<18}: {det:>6,}/{cnt:>6,}  Recall={rec*100:.2f}% [CI {lo*100:.1f}%-{hi*100:.1f}%]")
    return {"fpr": fpr, "recall": recall, "fa_per_million": fa_per_million}


def prepare_anomaly_features(X_supervised, sup_feature_cols, anom_feature_names, anomaly_scaler):
    """
    Given supervised-scaled data, we need to:
    1. Un-scale from supervised scaler
    2. Select anomaly features
    3. Apply anomaly scaler
    
    But we don't have the supervised scaler here easily, so instead:
    Map anomaly features to supervised feature indices, 
    then load unscaled data or inverse-transform.
    """
    # Load supervised scaler to inverse-transform
    sup_scaler = joblib.load(CLEAN_DIR / "scaler.pkl")
    
    # Inverse supervised scaling
    X_raw = sup_scaler.inverse_transform(X_supervised)
    
    # Select anomaly features from raw data
    # Some anomaly features (like Bwd Avg Bytes/Bulk) were dropped as zero-variance
    # in the supervised pipeline. These are essentially all-zero columns. Fill with 0.
    col_indices = []
    zero_fill_positions = []
    for i, af in enumerate(anom_feature_names):
        if af in sup_feature_cols:
            col_indices.append((i, sup_feature_cols.index(af)))
        else:
            zero_fill_positions.append((i, af))
    
    if zero_fill_positions:
        print(f"  INFO: {len(zero_fill_positions)} anomaly features not in supervised (zero-variance, filling with 0):")
        for pos, name in zero_fill_positions:
            print(f"    [{pos}] {name}")
    
    n_samples = X_raw.shape[0]
    X_anom_raw = np.zeros((n_samples, len(anom_feature_names)), dtype=np.float64)
    for anom_pos, sup_pos in col_indices:
        X_anom_raw[:, anom_pos] = X_raw[:, sup_pos]
    # zero_fill_positions already filled with 0 by np.zeros
    
    # Apply anomaly scaler
    X_anom_scaled = anomaly_scaler.transform(X_anom_raw)
    
    return X_anom_scaled


def run():
    print("=" * 75)
    print("ITEM 9: ANOMALY LAYER QUANTITATIVE REPORT (AE vs IF, per source)")
    print("=" * 75)

    # Load anomaly manifest
    with open(ANOMALY_DIR / "manifest.json", "r") as f:
        anom_manifest = json.load(f)
    threshold = anom_manifest["threshold"]
    cal = anom_manifest.get("calibration", {})
    print(f"Threshold (99th pctl Benign Val): {threshold:.6f}")
    print(f"FPR overall: {cal.get('fpr_overall', 'N/A')}")
    print(f"FPR UNSW:    {cal.get('fpr_unsw', 'N/A')}")
    print(f"FPR CIC:     {cal.get('fpr_cicids2017', 'N/A')}")

    # Load anomaly feature list and scaler
    with open(ANOMALY_DIR / "feature_names.json", "r") as f:
        anom_meta = json.load(f)
    anom_features = anom_meta["features"]
    anomaly_scaler = joblib.load(ANOMALY_DIR / "scaler_anomaly.pkl")
    print(f"Anomaly features: {len(anom_features)}")

    # Load ensemble
    print("Loading AnomalyEnsemble...")
    ensemble = AnomalyEnsemble.load(ANOMALY_DIR)

    # Supervised feature list
    with open(RUN_DIR / "manifest.json", "r") as f:
        manifest = json.load(f)
    sup_features = manifest["feature_columns"]

    # Label encoder
    with open(CLEAN_DIR / "label_encoder.pkl", "rb") as f:
        le = pickle.load(f)
    enc_classes = list(le.classes_)

    # ---- 2018 External ----
    x_2018_path = Path("data/processed/X_test_2018.npy")
    if x_2018_path.exists():
        X_2018_sup = np.load(x_2018_path)
        y_2018_b   = np.load("data/processed/y_test_2018_binary.npy")
        y_2018_m   = np.load("data/processed/y_test_2018_multi.npy")
        print(f"\n2018 shape: {X_2018_sup.shape} | Benign: {np.sum(y_2018_b==0):,} | Attack: {np.sum(y_2018_b==1):,}")

        # Prepare anomaly features from supervised-scaled data
        print("Preparing anomaly features (inverse sup_scaler → select → anom_scaler)...")
        X_anom_2018 = prepare_anomaly_features(X_2018_sup, sup_features, anom_features, anomaly_scaler)
        
        if X_anom_2018 is not None:
            print(f"Anomaly input shape: {X_anom_2018.shape}")
            nan_count = int(np.isnan(X_anom_2018).sum())
            inf_count = int(np.isinf(X_anom_2018).sum())
            print(f"NaN count: {nan_count} | Inf count: {inf_count}")
            
            if nan_count > 0 or inf_count > 0:
                print("Replacing NaN/Inf with 0...")
                X_anom_2018 = np.nan_to_num(X_anom_2018, nan=0.0, posinf=0.0, neginf=0.0)

            # Score
            scores_ens, scores_ae, scores_if = ensemble.predict_score(X_anom_2018)

            print("\n--- ENSEMBLE (AE+IF combined) ---")
            report_component("Ensemble", scores_ens, threshold, y_2018_b, y_2018_m, enc_classes, "2018 External")
            print("\n--- AUTOENCODER COMPONENT ---")
            report_component("AE", scores_ae, threshold, y_2018_b, y_2018_m, enc_classes, "2018 External (AE alone)")
            print("\n--- ISOLATION FOREST COMPONENT ---")
            report_component("IF", scores_if, threshold, y_2018_b, y_2018_m, enc_classes, "2018 External (IF alone)")

            # Infiltration focus
            try:
                infil_idx = enc_classes.index("Infiltration")
                infil_mask = (y_2018_m == infil_idx)
                infil_count = int(np.sum(infil_mask))
                if infil_count > 0:
                    det_ens = int(np.sum(scores_ens[infil_mask] >= threshold))
                    det_ae  = int(np.sum(scores_ae[infil_mask]  >= threshold))
                    det_if  = int(np.sum(scores_if[infil_mask]  >= threshold))

                    print(f"\n--- INFILTRATION FOCUS (2018, N={infil_count:,}) ---")
                    print(f"  Ensemble: {det_ens:,}/{infil_count:,} = {det_ens/infil_count*100:.2f}%")
                    print(f"  AE:       {det_ae:,}/{infil_count:,}  = {det_ae/infil_count*100:.2f}%")
                    print(f"  IF:       {det_if:,}/{infil_count:,}  = {det_if/infil_count*100:.2f}%")

                    infil_scores = scores_ens[infil_mask]
                    print(f"\n  Score quantiles (Ensemble) on Infiltration:")
                    for pctl in [0, 25, 50, 75, 95, 99, 100]:
                        val = np.percentile(infil_scores, pctl)
                        print(f"    P{pctl:>3}: {val:.6f}")

                    if det_ens == 0:
                        print("\n  >> CONCLUSION: Anomaly layer does NOT detect 2018 Infiltration.")
                        print("  >> 'detects Infiltration' claim MUST remain removed.")
                    else:
                        print(f"\n  >> Anomaly layer detects {det_ens/infil_count*100:.1f}% of 2018 Infiltration.")
            except ValueError:
                print("Infiltration not in encoder classes — skipping.")
        else:
            print("Could not prepare anomaly features — aborting 2018.")
    else:
        print("\n2018 test file not ready — skipping.")

    # ---- In-distribution Val & Test ----
    print("\n" + "=" * 75)
    print("ANOMALY on IN-DISTRIBUTION 2017 Val/Test")
    print("=" * 75)
    for split_name in ["val", "test"]:
        X_sup = np.load(CLEAN_DIR / f"X_{split_name}.npy")
        y_b   = np.load(CLEAN_DIR / f"y_{split_name}_binary.npy")
        X_anom = prepare_anomaly_features(X_sup, sup_features, anom_features, anomaly_scaler)
        if X_anom is not None:
            X_anom = np.nan_to_num(X_anom, nan=0.0, posinf=0.0, neginf=0.0)
            scores_e, _, _ = ensemble.predict_score(X_anom)
            report_component("Ensemble", scores_e, threshold, y_b, source_name=f"2017 {split_name.capitalize()}")

    print("\n" + "=" * 75)
    print("ITEM 9 COMPLETE")
    print("=" * 75)


if __name__ == "__main__":
    run()
