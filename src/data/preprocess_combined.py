"""
CSE-CIC-IDS2018 + CIC-IDS2017 Unified Preprocessor
Reads directly from 2018 ZIP and 2017 Parquets, harmonizes columns,
filters corrupt data/negative durations/infinities/duplicates/zero-variance,
smart-samples to balance all 8 attack classes, scales features, and saves.
"""
import gc
import json
import pickle
import zipfile
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from src.utils.config import settings
from src.utils.logger import logger

ZIP_PATH = Path(r"C:\Users\rzqm7\Downloads\dataset2018.zip")

# ── Column name mapping: CIC-IDS2018 → CIC-IDS2017 standard ──
COL_MAP_2018_TO_2017 = {
    "Dst Port":           "Destination Port",
    "Protocol":           "Protocol",
    "Flow Duration":      "Flow Duration",
    "Tot Fwd Pkts":       "Total Fwd Packets",
    "Tot Bwd Pkts":       "Total Backward Packets",
    "TotLen Fwd Pkts":    "Fwd Packets Length Total",
    "TotLen Bwd Pkts":    "Bwd Packets Length Total",
    "Fwd Pkt Len Max":    "Fwd Packet Length Max",
    "Fwd Pkt Len Min":    "Fwd Packet Length Min",
    "Fwd Pkt Len Mean":   "Fwd Packet Length Mean",
    "Fwd Pkt Len Std":    "Fwd Packet Length Std",
    "Bwd Pkt Len Max":    "Bwd Packet Length Max",
    "Bwd Pkt Len Min":    "Bwd Packet Length Min",
    "Bwd Pkt Len Mean":   "Bwd Packet Length Mean",
    "Bwd Pkt Len Std":    "Bwd Packet Length Std",
    "Flow Byts/s":        "Flow Bytes/s",
    "Flow Pkts/s":        "Flow Packets/s",
    "Flow IAT Mean":      "Flow IAT Mean",
    "Flow IAT Std":       "Flow IAT Std",
    "Flow IAT Max":       "Flow IAT Max",
    "Flow IAT Min":       "Flow IAT Min",
    "Fwd IAT Tot":        "Fwd IAT Total",
    "Fwd IAT Mean":       "Fwd IAT Mean",
    "Fwd IAT Std":        "Fwd IAT Std",
    "Fwd IAT Max":        "Fwd IAT Max",
    "Fwd IAT Min":        "Fwd IAT Min",
    "Bwd IAT Tot":        "Bwd IAT Total",
    "Bwd IAT Mean":       "Bwd IAT Mean",
    "Bwd IAT Std":        "Bwd IAT Std",
    "Bwd IAT Max":        "Bwd IAT Max",
    "Bwd IAT Min":        "Bwd IAT Min",
    "Fwd PSH Flags":      "Fwd PSH Flags",
    "Bwd PSH Flags":      "Bwd PSH Flags",
    "Fwd URG Flags":      "Fwd URG Flags",
    "Bwd URG Flags":      "Bwd URG Flags",
    "Fwd Header Len":     "Fwd Header Length",
    "Bwd Header Len":     "Bwd Header Length",
    "Fwd Pkts/s":         "Fwd Packets/s",
    "Bwd Pkts/s":         "Bwd Packets/s",
    "Pkt Len Min":        "Packet Length Min",
    "Pkt Len Max":        "Packet Length Max",
    "Pkt Len Mean":       "Packet Length Mean",
    "Pkt Len Std":        "Packet Length Std",
    "Pkt Len Var":        "Packet Length Variance",
    "FIN Flag Cnt":       "FIN Flag Count",
    "SYN Flag Cnt":       "SYN Flag Count",
    "RST Flag Cnt":       "RST Flag Count",
    "PSH Flag Cnt":       "PSH Flag Count",
    "ACK Flag Cnt":       "ACK Flag Count",
    "URG Flag Cnt":       "URG Flag Count",
    "CWE Flag Count":     "CWE Flag Count",
    "ECE Flag Cnt":       "ECE Flag Count",
    "Down/Up Ratio":      "Down/Up Ratio",
    "Pkt Size Avg":       "Avg Packet Size",
    "Fwd Seg Size Avg":   "Avg Fwd Segment Size",
    "Bwd Seg Size Avg":   "Avg Bwd Segment Size",
    "Fwd Byts/b Avg":     "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg":     "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg":   "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg":     "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg":     "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg":   "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts":   "Subflow Fwd Packets",
    "Subflow Fwd Byts":   "Subflow Fwd Bytes",
    "Subflow Bwd Pkts":   "Subflow Bwd Packets",
    "Subflow Bwd Byts":   "Subflow Bwd Bytes",
    "Init Fwd Win Byts":  "Init Fwd Win Bytes",
    "Init Bwd Win Byts":  "Init Bwd Win Bytes",
    "Fwd Act Data Pkts":  "Fwd Act Data Packets",
    "Fwd Seg Size Min":   "Fwd Seg Size Min",
    "Active Mean":        "Active Mean",
    "Active Std":         "Active Std",
    "Active Max":         "Active Max",
    "Active Min":         "Active Min",
    "Idle Mean":          "Idle Mean",
    "Idle Std":           "Idle Std",
    "Idle Max":           "Idle Max",
    "Idle Min":           "Idle Min",
    "Label":              "Label",
}

# ── Robust Label mapping: 2018 labels → unified 8 categories ──
def map_label_2018(raw) -> str:
    if pd.isna(raw):
        return None
    s = str(raw).lower().strip()
    if s in ("benign",):
        return "BENIGN"
    if "ddos" in s or "loic" in s or "hoic" in s:
        return "DDoS"
    if "dos" in s or "hulk" in s or "goldeneye" in s or "slowloris" in s or "slowhttp" in s:
        return "DoS"
    if "ftp" in s or "ssh" in s:
        return "BruteForce"
    if "brute force" in s:
        if "web" in s or "xss" in s:
            return "WebAttack"
        return "BruteForce"
    if "sql" in s or "xss" in s:
        return "WebAttack"
    if "bot" in s:
        return "Bot"
    if "infilter" in s or "infiltrat" in s:
        return "Infiltration"
    if s in ("label", "", "nan", "null"):
        return None
    return "BENIGN"


def map_label_2017(raw) -> str:
    if pd.isna(raw):
        return "BENIGN"
    s = str(raw).lower().strip()
    if "benign" in s:
        return "BENIGN"
    if "ddos" in s:
        return "DDoS"
    if "dos" in s or "heartbleed" in s:
        return "DoS"
    if "portscan" in s:
        return "PortScan"
    if "patator" in s:
        return "BruteForce"
    if "bot" in s:
        return "Bot"
    if "web attack" in s or "xss" in s or "sql" in s:
        return "WebAttack"
    if "infiltration" in s:
        return "Infiltration"
    return "BENIGN"


def sanitize_dataframe(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    """Filter out corrupt values, negative durations, NaNs, infinities."""
    # Keep only feature columns + Category
    cols = [c for c in feature_cols if c in df.columns] + ["Category"]
    df = df[cols].copy()

    # Convert numeric feature columns
    for c in feature_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    # Replace infinities
    df.replace([float("inf"), float("-inf")], float("nan"), inplace=True)
    df.dropna(inplace=True)

    # Filter negative flow duration
    if "Flow Duration" in df.columns:
        df = df[df["Flow Duration"] >= 0]

    # Convert features to float32 to save RAM
    num_cols = [c for c in feature_cols if c in df.columns]
    df[num_cols] = df[num_cols].astype(np.float32)

    return df


def load_2018_from_zip(target_features: list[str]) -> pd.DataFrame:
    """
    Read CIC-IDS2018 CSVs from ZIP, harmonize columns,
    filter corrupt data, and sample balanced attack flows.
    """
    logger.info("=" * 60)
    logger.info("Loading CSE-CIC-IDS2018 from ZIP...")
    logger.info("=" * 60)

    # Max attack flows per file to prevent DoS/DDoS from flooding memory
    # Keep 100% of WebAttack (SQL Injection / XSS) and Infiltration
    MAX_ATTACKS_PER_FILE = {
        "02-22-2018.csv": None,    # 100% WebAttack (SQL Injection, XSS)
        "02-23-2018.csv": None,    # 100% WebAttack (SQL Injection, XSS)
        "02-28-2018.csv": 45000,   # Infiltration
        "03-01-2018.csv": 45000,   # Infiltration
        "03-02-2018.csv": 45000,   # Bot
        "02-14-2018.csv": 45000,   # BruteForce
        "02-15-2018.csv": 45000,   # DoS
        "02-16-2018.csv": 45000,   # DoS
        "02-20-2018.csv": 45000,   # DDoS LOIC-HTTP (cap so we don't scan 7M benign rows)
        "02-21-2018.csv": 45000,   # DDoS HOIC
    }
    MAX_BENIGN_PER_FILE = 15000

    all_dfs = []

    with zipfile.ZipFile(ZIP_PATH, "r") as z:
        csv_files = [n for n in z.namelist() if n.endswith(".csv")]
        logger.info(f"Found {len(csv_files)} CSV files in ZIP archive")

        for csv_name in sorted(csv_files):
            max_atk = MAX_ATTACKS_PER_FILE.get(csv_name, 45000)
            logger.info(f"  Reading {csv_name} (max_attacks={max_atk}, max_benign={MAX_BENIGN_PER_FILE})...")

            file_attacks = []
            file_benign = []
            benign_count = 0
            attack_count = 0

            with z.open(csv_name) as f:
                chunks = pd.read_csv(f, low_memory=False, chunksize=100000)

                for chunk in chunks:
                    chunk.columns = chunk.columns.str.strip()
                    chunk = chunk.rename(columns=COL_MAP_2018_TO_2017)

                    if "Label" not in chunk.columns:
                        continue

                    chunk["Category"] = chunk["Label"].apply(map_label_2018)
                    chunk = chunk[chunk["Category"].notna()]

                    # Separate attacks and benign
                    attacks = chunk[chunk["Category"] != "BENIGN"]
                    benign = chunk[chunk["Category"] == "BENIGN"]

                    # Collect attacks
                    if len(attacks) > 0:
                        if max_atk is not None:
                            rem_atk = max_atk - attack_count
                            if rem_atk > 0:
                                atk_sample = attacks.head(rem_atk)
                                file_attacks.append(atk_sample)
                                attack_count += len(atk_sample)
                        else:
                            file_attacks.append(attacks)
                            attack_count += len(attacks)

                    # Collect benign
                    if benign_count < MAX_BENIGN_PER_FILE and len(benign) > 0:
                        rem_ben = MAX_BENIGN_PER_FILE - benign_count
                        ben_sample = benign.head(rem_ben)
                        file_benign.append(ben_sample)
                        benign_count += len(ben_sample)

                    # If both limits reached, stop reading remaining chunks of this file
                    if max_atk is not None and attack_count >= max_atk and benign_count >= MAX_BENIGN_PER_FILE:
                        logger.info(f"    Limits reached for {csv_name}, skipping remainder of file")
                        break

            # Concatenate chunks for this file
            parts = file_attacks + file_benign
            if parts:
                file_df = pd.concat(parts, ignore_index=True)
                # Sanitize immediately to free memory
                file_df = sanitize_dataframe(file_df, target_features)
                all_dfs.append(file_df)
                logger.info(f"    ✔ Loaded {attack_count:,} attacks + {benign_count:,} benign = {len(file_df):,} flows")

            gc.collect()

    df_2018 = pd.concat(all_dfs, ignore_index=True)
    logger.success(f"2018 dataset loaded: {len(df_2018):,} clean flows")
    return df_2018


def load_2017_raw(target_features: list[str]) -> pd.DataFrame:
    """Load and sample 2017 raw data from parquets."""
    import glob
    logger.info("=" * 60)
    logger.info("Loading CIC-IDS2017 raw data from parquets...")
    logger.info("=" * 60)

    files = sorted(glob.glob(str(settings.data_raw_dir / "*.parquet")))
    all_dfs = []

    # Sampling caps per 2017 file
    MAX_PER_ATTACK_TYPE = 50000

    for f in files:
        df = pd.read_parquet(f)
        df.columns = df.columns.str.strip()
        df["Category"] = df["Label"].apply(map_label_2017)

        attacks = df[df["Category"] != "BENIGN"]
        benign = df[df["Category"] == "BENIGN"]

        parts = []
        # Rare attacks: keep 100%
        if "WebAttacks" in f or "Infiltration" in f or "Botnet" in f:
            parts.append(attacks)
            parts.append(benign.head(15000))
        elif "Benign" in f:
            # Monday is pure benign: sample 100,000
            parts.append(benign.sample(n=min(len(benign), 100000), random_state=settings.random_seed))
        else:
            # Portscan, DoS, DDoS, Bruteforce
            if len(attacks) > MAX_PER_ATTACK_TYPE:
                attacks_sampled = attacks.sample(n=MAX_PER_ATTACK_TYPE, random_state=settings.random_seed)
            else:
                attacks_sampled = attacks
            parts.append(attacks_sampled)
            parts.append(benign.head(15000))

        file_df = pd.concat(parts, ignore_index=True)
        file_df = sanitize_dataframe(file_df, target_features)
        all_dfs.append(file_df)
        logger.info(f"  {Path(f).name}: {len(file_df):,} clean flows")

    df_2017 = pd.concat(all_dfs, ignore_index=True)
    logger.success(f"2017 dataset loaded: {len(df_2017):,} clean flows")
    return df_2017


def run():
    logger.info("=" * 65)
    logger.info("COMBINED CIC-IDS2017 + CSE-CIC-IDS2018 HIGH PERFORMANCE PIPELINE")
    logger.info("=" * 65)

    # 1. Target features from previous metadata
    meta_path = settings.data_processed_dir / "metadata.json"
    with open(meta_path, "r", encoding="utf-8") as f:
        meta_prev = json.load(f)
    target_features = meta_prev["feature_columns"]
    logger.info(f"Target feature count: {len(target_features)}")

    # 2. Load and filter 2017
    df_2017 = load_2017_raw(target_features)

    # 3. Load and filter 2018
    df_2018 = load_2018_from_zip(target_features)

    # 4. Fill any missing columns in either dataframe with 0.0
    for col in target_features:
        if col not in df_2017.columns:
            df_2017[col] = 0.0
        if col not in df_2018.columns:
            df_2018[col] = 0.0

    df_2017 = df_2017[target_features + ["Category"]]
    df_2018 = df_2018[target_features + ["Category"]]

    # 5. Merge datasets
    logger.info("\n" + "=" * 60)
    logger.info("Merging and Final Sanitization...")
    logger.info("=" * 60)
    df = pd.concat([df_2017, df_2018], ignore_index=True)
    del df_2017, df_2018
    gc.collect()

    # Drop exact duplicates
    dup_before = len(df)
    df.drop_duplicates(inplace=True)
    logger.info(f"Dropped {dup_before - len(df):,} exact duplicates")

    # Drop zero variance
    zero_var = [c for c in target_features if df[c].std() == 0.0]
    if zero_var:
        logger.info(f"Dropped {len(zero_var)} zero-variance features: {zero_var}")
        target_features_clean = [c for c in target_features if c not in zero_var]
        df.drop(columns=zero_var, inplace=True)
    else:
        target_features_clean = target_features

    # 6. Balanced Sampling: Target ~1.5:1 BENIGN to Attack ratio
    logger.info("\nBalancing dataset...")
    attacks = df[df["Category"] != "BENIGN"]
    benign = df[df["Category"] == "BENIGN"]
    n_attacks = len(attacks)
    n_benign_target = min(len(benign), int(n_attacks * 1.5))

    logger.info(f"  Total Attacks (100% retained): {n_attacks:,}")
    logger.info(f"  Original BENIGN: {len(benign):,} → Sampling {n_benign_target:,} (1.5:1 ratio)")

    benign_sampled = benign.sample(n=n_benign_target, random_state=settings.random_seed)
    df_balanced = pd.concat([attacks, benign_sampled], ignore_index=True)
    df_balanced = df_balanced.sample(frac=1.0, random_state=settings.random_seed).reset_index(drop=True)

    del attacks, benign, benign_sampled, df
    gc.collect()

    logger.info("\nCombined Final Class Distribution:")
    for cat, cnt in df_balanced["Category"].value_counts().items():
        pct = cnt / len(df_balanced) * 100
        logger.info(f"  {cat:<16} {cnt:>10,}  ({pct:5.2f}%)")

    # 7. Encode Labels
    le = LabelEncoder()
    # Force the standard class ordering
    expected_classes = ["BENIGN", "Bot", "BruteForce", "DDoS", "DoS", "Infiltration", "PortScan", "WebAttack"]
    le.fit(expected_classes)

    # Filter out any unexpected category if any
    df_balanced = df_balanced[df_balanced["Category"].isin(expected_classes)].reset_index(drop=True)

    y_multi = le.transform(df_balanced["Category"])
    y_binary = (df_balanced["Category"] != "BENIGN").astype(np.int32).values

    X = df_balanced[target_features_clean].astype(np.float32).values

    logger.info(f"\nMatrix Shape: {X.shape} ({X.shape[0]:,} flows, {X.shape[1]} features)")

    # 8. Train/Test Stratified Split (80/20)
    logger.info("Splitting 80/20 stratified...")
    X_train, X_test, y_train_b, y_test_b, y_train_m, y_test_m = train_test_split(
        X, y_binary, y_multi,
        test_size=0.20,
        random_state=settings.random_seed,
        stratify=y_multi,
    )

    del df_balanced, X, y_binary, y_multi
    gc.collect()

    # 9. Feature Scaling
    logger.info("Fitting StandardScaler on training data...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    del X_train, X_test
    gc.collect()

    # 10. Save Processed Artifacts
    out = settings.data_processed_dir
    out.mkdir(parents=True, exist_ok=True)
    logger.info(f"Saving preprocessed data to {out}...")

    np.save(out / "X_train.npy", X_train_s)
    np.save(out / "X_test.npy", X_test_s)
    np.save(out / "y_train_binary.npy", y_train_b)
    np.save(out / "y_test_binary.npy", y_test_b)
    np.save(out / "y_train_multi.npy", y_train_m)
    np.save(out / "y_test_multi.npy", y_test_m)

    with open(out / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(out / "label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)

    meta = {
        "n_features": len(target_features_clean),
        "feature_columns": target_features_clean,
        "class_names": list(le.classes_),
        "n_train": len(X_train_s),
        "n_test": len(X_test_s),
        "datasets": ["CICIDS2017", "CSE-CIC-IDS2018"],
        "filtered": True,
    }
    with open(out / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    logger.success("=" * 65)
    logger.success("✔ Combined CIC-IDS2017 + CSE-CIC-IDS2018 Preprocessing Complete!")
    logger.info(f"  Total Clean Flows: {meta['n_train'] + meta['n_test']:,}")
    logger.info(f"  Training Set:     {meta['n_train']:,}")
    logger.info(f"  Testing Set:      {meta['n_test']:,}")
    logger.info(f"  Clean Features:   {meta['n_features']}")
    logger.info(f"  Classes:          {meta['class_names']}")
    logger.success("=" * 65)


if __name__ == "__main__":
    run()
