"""Prepare a CSE-CIC-IDS2018 TEST set for the models trained on CICIDS2017.

Same inputs and output file names as the previous version (X_test_2018.npy, y_test_2018_*.npy,
metadata_2018.json). What changed, and why:

  * Random sampling. The old code kept the FIRST rows of each file (head()), so it took the
    first minutes of every day as BENIGN and, for each attack class, only the first variant
    that appears in the files. Now every row of every file has the same chance of being kept.
  * Caps are applied per ORIGINAL label (GoldenEye, Slowloris, Hulk, LOIC-HTTP, HOIC, ...),
    not per merged class, so every attack variant is represented. In 2018 Infiltration is not
    rare (about 160 thousand rows), so it is capped like the others instead of being kept 100%.
  * The original label of each row is saved (y_test_2018_labels_raw.npy), so the sample can be
    audited later.
  * A missing feature stops the run (it used to be silently filled with 0).
  * NaN / Inf handling is an explicit choice (--nan-policy) and must match the 2017 pipeline.
  * Unknown labels and every dropped row are counted and written to metadata_2018.json.
  * Scaling is still transform-only with the 2017 scaler, labels still use the 2017 encoder.

Example
  python -m src.data.prepare_2018_v2 --nan-policy drop
"""
import argparse
import json
import pickle
import time
from collections import Counter
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd

from src.utils.config import settings
from src.utils.logger import logger

COLUMN_MAPPING = {
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Fwd Packets Length Total",
    "TotLen Bwd Pkts": "Bwd Packets Length Total",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Packet Length Min",
    "Pkt Len Max": "Packet Length Max",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Pkt Size Avg": "Avg Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    # bulk features: added so the mapping is complete, in case the 2017 feature list contains them
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init Fwd Win Bytes",
    "Init Bwd Win Byts": "Init Bwd Win Bytes",
    "Fwd Act Data Pkts": "Fwd Act Data Packets",
}

CLASSES_2018 = ["BENIGN", "Bot", "BruteForce", "DDoS", "DoS", "Infiltration", "WebAttack"]


def map_label_2018(raw: str) -> str:
    s = str(raw).strip().lower()
    if s == "label":
        return "HEADER"
    if "benign" in s:
        return "BENIGN"
    # Web attacks must precede generic bruteforce because of 'Brute Force -Web' and 'Brute Force -XSS'
    if "web" in s or "xss" in s or "sql" in s:
        return "WebAttack"
    if "ddos" in s:
        return "DDoS"
    if "dos" in s or "heartbleed" in s:
        return "DoS"
    if "portscan" in s:
        return "PortScan"
    if "patator" in s or "bruteforce" in s or "brute force" in s:
        return "BruteForce"
    if "bot" in s:
        return "Bot"
    if "infilt" in s:  # covers infiltration and infilteration
        return "Infiltration"
    return "UNKNOWN"


def extract_sampled_2018(
    raw_dir: Path,
    expected_features: List[str],
    samples_per_label: int = 10_000,
    benign_total: int = 60_000,
    nan_policy: str = "drop",
    chunksize: int = 100_000,
    seed: int = 42,
):
    """Uniform random sample over ALL files: up to `samples_per_label` rows for each original
    attack label and `benign_total` BENIGN rows. Returns (DataFrame, stats dict)."""
    files = sorted(raw_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {raw_dir}")

    rng = np.random.default_rng(seed)
    wanted_raw = set(expected_features) | {"Label"} | {
        k for k, v in COLUMN_MAPPING.items() if v in set(expected_features)
    }
    kept = {}                        # group -> DataFrame holding the rows kept so far
    available = Counter()            # cleaned rows seen per original label
    unknown = Counter()
    stats = Counter()
    logger.info(f"Scanning {len(files)} CSE-CIC-IDS2018 files from: {raw_dir}")

    for f in files:
        t0 = time.time()
        logger.info(f"Processing {f.name} ({f.stat().st_size / (1024 * 1024):.1f} MB)...")
        reader = pd.read_csv(f, chunksize=chunksize, low_memory=False,
                             usecols=lambda c: str(c).strip() in wanted_raw)
        for chunk in reader:
            chunk.columns = chunk.columns.str.strip()
            chunk = chunk.rename(columns=COLUMN_MAPPING)
            if "Label" not in chunk.columns:
                raise ValueError(f"{f.name}: no 'Label' column")
            missing = [c for c in expected_features if c not in chunk.columns]
            if missing:
                raise ValueError(f"{f.name}: missing features after column mapping: {missing}")
            stats["rows_read"] += len(chunk)

            raw = chunk["Label"].astype(str).str.strip()
            is_header = raw.str.lower() == "label"          # header row repeated inside the data
            stats["repeated_header_rows"] += int(is_header.sum())
            chunk, raw = chunk[~is_header], raw[~is_header]
            if chunk.empty:
                continue

            cat_of = {r: map_label_2018(r) for r in raw.unique()}
            category = raw.map(cat_of)
            is_known = category.isin(CLASSES_2018)
            unknown.update(raw[~is_known])
            chunk, raw, category = chunk[is_known], raw[is_known], category[is_known]
            if chunk.empty:
                continue

            X = chunk[expected_features].apply(pd.to_numeric, errors="coerce")
            X = X.replace([np.inf, -np.inf], np.nan)

            # same rule as before: drop missing / negative Flow Duration
            if "Flow Duration" in X.columns:
                bad = ~(X["Flow Duration"] >= 0)
                stats["bad_flow_duration"] += int(bad.sum())
                X, raw, category = X[~bad], raw[~bad], category[~bad]

            has_nan = X.isna().any(axis=1)
            if nan_policy == "drop":
                stats["rows_dropped_nan_inf"] += int(has_nan.sum())
                X, raw, category = X[~has_nan], raw[~has_nan], category[~has_nan]
            else:  # "zero"
                stats["rows_zero_filled_nan_inf"] += int(has_nan.sum())
                X = X.fillna(0.0)
            if X.empty:
                continue

            part = X.copy()
            part["label_category"] = category.to_numpy()
            part["raw_label"] = raw.to_numpy()
            part["_group"] = np.where(category.to_numpy() == "BENIGN", "BENIGN", raw.str.lower().to_numpy())
            part["_key"] = rng.random(len(part))
            available.update(part["_group"])

            for g, sub in part.groupby("_group"):
                cap = benign_total if g == "BENIGN" else samples_per_label
                cur = sub if g not in kept else pd.concat([kept[g], sub], ignore_index=True)
                kept[g] = cur.nsmallest(cap, "_key")
        logger.info(f"  done in {time.time() - t0:.0f}s")

    if not kept:
        raise RuntimeError("No usable rows found. Check the label names and the cleaning counts.")
    df = pd.concat(kept.values(), ignore_index=True)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    stats = {k: int(v) for k, v in stats.items()}
    stats["unknown_labels_dropped"] = dict(unknown)
    stats["rows_available_per_label"] = {k: int(v) for k, v in sorted(available.items())}
    logger.info(f"Total sampled 2018 flows: {len(df):,}")
    logger.info("Sample (rows kept / rows available) per original label:")
    for g, n_kept in df["_group"].value_counts().items():
        logger.info(f"  {g:<28}: {n_kept:>8,} / {available[g]:>10,}")
    if unknown:
        logger.warning(f"Rows dropped because the label is unknown: {dict(unknown)}")
    return df, stats


def prepare_and_save_2018(raw_dir: Path, samples_per_label: int, benign_total: int,
                          nan_policy: str, seed: int):
    processed_dir = settings.data_processed_dir

    # Load 2017 metadata, scaler, label_encoder
    with open(processed_dir / "metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)
    with open(processed_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    with open(processed_dir / "label_encoder.pkl", "rb") as f:
        le = pickle.load(f)

    expected_features = meta["feature_columns"]
    logger.info(f"Loaded 2017 metadata: expecting {len(expected_features)} features.")

    df, stats = extract_sampled_2018(raw_dir, expected_features, samples_per_label,
                                     benign_total, nan_policy, seed=seed)

    # Reorder columns to match EXACTLY the 2017 feature order, then transform with the 2017 scaler (NO FIT)
    X_df = df[expected_features].astype(np.float64)
    n_in = getattr(scaler, "n_features_in_", len(expected_features))
    if n_in != len(expected_features):
        raise RuntimeError(f"Scaler expects {n_in} features but metadata lists {len(expected_features)}.")
    names_in = getattr(scaler, "feature_names_in_", None)
    if names_in is not None and list(names_in) != list(expected_features):
        raise RuntimeError("Scaler was fitted on different feature names/order than metadata['feature_columns'].")
    logger.info("Applying pre-fitted scaler (transform only, zero fit)...")
    # pass a plain array when the scaler was fitted on one (avoids sklearn's feature-name warning)
    X_scaled = scaler.transform(X_df if names_in is not None else X_df.to_numpy()).astype(np.float32)
    if not np.isfinite(X_scaled).all():
        raise RuntimeError("Non-finite values after scaling.")

    # Binary labels: 0 for BENIGN, 1 for Attack
    y_binary = (df["label_category"] != "BENIGN").astype(np.int32).values

    # Multi-class labels: transform using the 2017 label encoder
    # Note: PortScan is in le.classes_, but not in 2018.
    y_multi = le.transform(df["label_category"])

    out_dir = processed_dir
    np.save(out_dir / "X_test_2018.npy", X_scaled)
    np.save(out_dir / "y_test_2018_binary.npy", y_binary)
    np.save(out_dir / "y_test_2018_multi.npy", y_multi)
    np.save(out_dir / "y_test_2018_categories.npy", df["label_category"].to_numpy().astype(str))
    np.save(out_dir / "y_test_2018_labels_raw.npy", df["raw_label"].to_numpy().astype(str))

    present = set(df["label_category"].unique())
    info_2018 = {
        "n_samples": int(len(X_scaled)),
        "n_features": int(X_scaled.shape[1]),
        "classes_present": sorted(present),
        "class_distribution": {k: int(v) for k, v in df["label_category"].value_counts().items()},
        "raw_label_distribution": {k: int(v) for k, v in df["raw_label"].value_counts().items()},
        "missing_class_vs_2017": [c for c in meta["class_names"] if c not in present],
        "sampling": {"method": "uniform random over all files", "samples_per_label": samples_per_label,
                     "benign_total": benign_total, "seed": seed, "nan_policy": nan_policy},
        "cleaning": stats,
    }
    with open(out_dir / "metadata_2018.json", "w", encoding="utf-8") as f:
        json.dump(info_2018, f, indent=2)

    logger.success(f"2018 Test Set successfully prepared and saved to {out_dir}!")
    logger.info(f"Missing class vs 2017: {info_2018['missing_class_vs_2017']}")
    return info_2018


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path,
                    default=Path(r"C:\Users\rzqm7\OneDrive\Desktop\datasets\cic ids 2018\dataset2018"))
    ap.add_argument("--samples-per-label", type=int, default=10_000,
                    help="Max rows kept for each ORIGINAL attack label")
    ap.add_argument("--benign-total", type=int, default=60_000, help="BENIGN rows kept over all files")
    ap.add_argument("--nan-policy", required=True, choices=["drop", "zero"],
                    help="What the 2017 preprocessor did with NaN/Inf rows: drop them, or fill with 0")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    prepare_and_save_2018(args.raw_dir, args.samples_per_label, args.benign_total,
                          args.nan_policy, args.seed)