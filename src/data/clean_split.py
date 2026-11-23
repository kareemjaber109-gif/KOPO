"""
Clean Sequential Block Split for CIC-IDS2017 Benchmark (Phase 1)
- Strict map_label with ValueError on unknown labels
- Near-deduplication (exact + float rounded to 3 decimals)
- Sequential block splitting per class: Train (70%) | Gap 1 (5%) | Val (10%) | Gap 2 (5%) | Test (10%)
- Scaling fitted exclusively on Train
"""
import json
import pickle
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

from src.utils.config import settings
from src.utils.logger import logger


CLASSES = [
    "BENIGN",
    "Bot",
    "BruteForce",
    "DDoS",
    "DoS",
    "Infiltration",
    "PortScan",
    "WebAttack",
]


def map_label(raw: str) -> str:
    """
    Strict label mapper.
    Maps known attack and benign strings to standard SOC class names.
    Raises ValueError on unknown labels (never silently falls back to BENIGN).
    """
    s = str(raw).strip().lower()
    if "benign" in s:
        return "BENIGN"
    if "bot" in s:
        return "Bot"
    if "patator" in s:
        return "BruteForce"
    if "ddos" in s:
        return "DDoS"
    if "dos" in s or "heartbleed" in s:
        return "DoS"
    if "portscan" in s:
        return "PortScan"
    if "web attack" in s or "xss" in s or "sql" in s:
        return "WebAttack"
    if "infiltration" in s:
        return "Infiltration"
    raise ValueError(f"CRITICAL PROTOCOL VIOLATION: Unknown raw flow label: {raw!r}")


def run_clean_split(output_dir: Path | None = None) -> Dict[str, any]:
    raw_dir = settings.data_raw_dir
    if output_dir is None:
        output_dir = settings.data_processed_dir / "clean"
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 65)
    logger.info("▶ Starting Phase 1 Clean Sequential Block Split on CIC-IDS2017")
    logger.info("=" * 65)

    with open(settings.data_processed_dir / "metadata.json", "r", encoding="utf-8") as f:
        meta_ref = json.load(f)
    feature_cols = meta_ref["feature_columns"]

    # 1. Load Parquets in chronological order
    parquets = sorted(raw_dir.glob("*.parquet"))
    if not parquets:
        raise FileNotFoundError(f"No parquet files found in {raw_dir}")

    logger.info(f"Loading {len(parquets)} CIC-IDS2017 parquet files...")
    dfs = []
    for p in parquets:
        df = pd.read_parquet(p)
        df.columns = df.columns.str.strip()
        # Verify required features present
        missing = [c for c in feature_cols if c not in df.columns]
        if missing:
            raise ValueError(f"File {p.name} missing features: {missing}")
        
        # Keep feature cols + Label
        df = df[feature_cols + ["Label"]].copy()
        df["mapped_label"] = df["Label"].apply(map_label)
        dfs.append(df)
        logger.info(f"  {p.name}: {len(df):,} flows")

    full_df = pd.concat(dfs, ignore_index=True)
    n_raw = len(full_df)
    logger.info(f"Total raw flows loaded: {n_raw:,}")

    # 2. Filtering NaNs, Infs, Corrupt Durations
    logger.info("\nFiltering NaNs, Infs, and corrupt negative durations...")
    full_df.replace([float("inf"), float("-inf")], float("nan"), inplace=True)
    full_df.dropna(subset=feature_cols, inplace=True)
    if "Flow Duration" in full_df.columns:
        full_df = full_df[full_df["Flow Duration"] >= 0]
    n_filtered = len(full_df)
    logger.info(f"Valid non-corrupt flows: {n_filtered:,} (dropped {n_raw - n_filtered:,})")

    # 3. Near-Deduplication
    # Step A: Exact deduplication across feature columns
    full_df.drop_duplicates(subset=feature_cols, inplace=True)
    n_exact_dedup = len(full_df)
    logger.info(f"Flows after exact deduplication: {n_exact_dedup:,} (dropped {n_filtered - n_exact_dedup:,})")

    # Step B: Near-deduplication (round float statistics to 3 decimals)
    float_cols = full_df[feature_cols].select_dtypes(include=[np.floating]).columns.tolist()
    rounded_floats = full_df[float_cols].round(3)
    non_floats = full_df[[c for c in feature_cols if c not in float_cols]]
    near_dup_mask = pd.concat([non_floats, rounded_floats, full_df[["mapped_label"]]], axis=1).duplicated()
    full_df = full_df[~near_dup_mask].copy()
    n_clean = len(full_df)
    logger.info(f"Flows after near-deduplication: {n_clean:,} (dropped {n_exact_dedup - n_clean:,})")

    # 4. Sequential Block Splitting per class
    # Protocol: Train (70%) | Gap 1 (5%) | Val (10%) | Gap 2 (5%) | Test (10%)
    logger.info("\n" + "-" * 60)
    logger.info("Executing Sequential Block Splitting per class (70% | 5% | 10% | 5% | 10%)")
    logger.info("-" * 60)

    train_indices = []
    val_indices = []
    test_indices = []
    gap_indices = []

    split_stats = {}

    for cname in CLASSES:
        class_mask = (full_df["mapped_label"] == cname)
        c_indices = full_df.index[class_mask].to_numpy()
        N = len(c_indices)

        if N == 0:
            logger.warning(f"Class '{cname}' has 0 samples!")
            continue

        # Infiltration in 2017 has only ~36 flows -> Non-evaluatable supervised
        if cname == "Infiltration":
            # Assign all to training / anomaly baseline, exclude from supervised test set
            train_indices.extend(c_indices)
            split_stats[cname] = {
                "total": N,
                "train": N,
                "val": 0,
                "test": 0,
                "note": "Non-evaluatable supervised (N < 50); evaluated via Anomaly Detection",
            }
            logger.info(f"  {cname:15}: Total={N:7,} | Train={N:6,} | Val=0 | Test=0 (Anomaly only)")
            continue

        idx_train_end = int(0.70 * N)
        idx_gap1_end  = int(0.75 * N)
        idx_val_end   = int(0.85 * N)
        idx_gap2_end  = int(0.90 * N)

        c_train = c_indices[:idx_train_end]
        c_gap1  = c_indices[idx_train_end:idx_gap1_end]
        c_val   = c_indices[idx_gap1_end:idx_val_end]
        c_gap2  = c_indices[idx_val_end:idx_gap2_end]
        c_test  = c_indices[idx_gap2_end:]

        train_indices.extend(c_train)
        gap_indices.extend(c_gap1)
        val_indices.extend(c_val)
        gap_indices.extend(c_gap2)
        test_indices.extend(c_test)

        split_stats[cname] = {
            "total": N,
            "train": len(c_train),
            "gap1": len(c_gap1),
            "val": len(c_val),
            "gap2": len(c_gap2),
            "test": len(c_test),
        }
        logger.info(
            f"  {cname:15}: Total={N:7,} | Train={len(c_train):6,} | Gap1={len(c_gap1):5,} | "
            f"Val={len(c_val):5,} | Gap2={len(c_gap2):5,} | Test={len(c_test):5,}"
        )

    # 5. Extract Train, Val, Test arrays
    train_df = full_df.loc[train_indices].copy()
    val_df   = full_df.loc[val_indices].copy()
    test_df  = full_df.loc[test_indices].copy()

    logger.info(f"\nFinal Split Sizes:")
    logger.info(f"  Train : {len(train_df):,} flows")
    logger.info(f"  Val   : {len(val_df):,} flows")
    logger.info(f"  Test  : {len(test_df):,} flows (HELD OUT — TO BE EVALUATED ONCE AT END)")
    logger.info(f"  Gaps  : {len(gap_indices):,} flows (completely discarded buffer)")

    X_train_raw = train_df[feature_cols].to_numpy(dtype=np.float32)
    X_val_raw   = val_df[feature_cols].to_numpy(dtype=np.float32)
    X_test_raw  = test_df[feature_cols].to_numpy(dtype=np.float32)

    # 6. Fit StandardScaler EXCLUSIVELY on Train split
    logger.info("\nFitting StandardScaler strictly on Train split...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_val   = scaler.transform(X_val_raw)
    X_test  = scaler.transform(X_test_raw)

    # 7. Labels
    le = LabelEncoder()
    le.fit(CLASSES)

    y_train_multi = le.transform(train_df["mapped_label"].to_numpy())
    y_val_multi   = le.transform(val_df["mapped_label"].to_numpy())
    y_test_multi  = le.transform(test_df["mapped_label"].to_numpy())

    y_train_binary = (train_df["mapped_label"].to_numpy() != "BENIGN").astype(np.int8)
    y_val_binary   = (val_df["mapped_label"].to_numpy() != "BENIGN").astype(np.int8)
    y_test_binary  = (test_df["mapped_label"].to_numpy() != "BENIGN").astype(np.int8)

    # 8. Persist Arrays & Artifacts
    logger.info(f"\nSaving clean split arrays to {output_dir}...")
    np.save(output_dir / "X_train.npy", X_train)
    np.save(output_dir / "y_train_multi.npy", y_train_multi)
    np.save(output_dir / "y_train_binary.npy", y_train_binary)

    np.save(output_dir / "X_val.npy", X_val)
    np.save(output_dir / "y_val_multi.npy", y_val_multi)
    np.save(output_dir / "y_val_binary.npy", y_val_binary)

    np.save(output_dir / "X_test.npy", X_test)
    np.save(output_dir / "y_test_multi.npy", y_test_multi)
    np.save(output_dir / "y_test_binary.npy", y_test_binary)

    with open(output_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(output_dir / "label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)

    manifest_metadata = {
        "dataset": "CIC-IDS2017 Clean Benchmark",
        "protocol": "Sequential Block Split with dual buffer gaps per class (Train 70% | Gap 5% | Val 10% | Gap 5% | Test 10%)",
        "n_raw": n_raw,
        "n_filtered": n_filtered,
        "n_clean_after_dedup": n_clean,
        "n_train": len(train_df),
        "n_val": len(val_df),
        "n_test": len(test_df),
        "n_gaps_discarded": len(gap_indices),
        "feature_columns": feature_cols,
        "n_features": len(feature_cols),
        "class_names": CLASSES,
        "class_splits": split_stats,
        "test_evaluation_rule": "Test set held out strictly for final evaluation. Zero tuning on Test.",
    }
    with open(output_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(manifest_metadata, f, indent=2)

    logger.success(f"Phase 1 Clean Split successfully generated in {output_dir}")
    return manifest_metadata


if __name__ == "__main__":
    run_clean_split()
