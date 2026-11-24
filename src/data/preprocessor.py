import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from tqdm import tqdm
from src.utils.config import settings
from src.utils.logger import logger

DROP_COLS = [
    "Flow ID", "Source IP", "Source Port",
    "Destination IP", "Timestamp",
]


def map_label(raw: str) -> str:
    """Robust string-based label mapping that handles encoding artifacts."""
    s = str(raw).lower()
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
    raise ValueError(f"CRITICAL PROTOCOL VIOLATION: Unknown raw flow label: '{raw}'")


def load_raw() -> pd.DataFrame:
    raw_dir  = settings.data_raw_dir
    parquets = sorted(raw_dir.glob("*.parquet"))
    csvs     = sorted(raw_dir.glob("*.csv"))

    files = parquets if parquets else csvs

    if not files:
        raise FileNotFoundError(
            "No data files found in data/raw/. "
            "Please ensure raw dataset files are placed in data/raw/"
        )

    logger.info(f"Loading {len(files)} file(s)...")
    dfs = []
    for f in tqdm(files, desc="Loading"):
        if f.suffix == ".parquet":
            df = pd.read_parquet(f)
        else:
            df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)
        logger.info(f"  {f.name}: {len(df):,} rows")

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Total raw flows: {len(combined):,} rows")
    return combined


def clean_and_filter(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("\n" + "=" * 50)
    logger.info("▶ Comprehensive Dataset Filtering & Sanitization")
    logger.info("=" * 50)
    original = len(df)

    # 1. Drop metadata / IP columns
    df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)

    # 2. Handle inf and nan
    df.replace([float("inf"), float("-inf")], float("nan"), inplace=True)
    df.dropna(inplace=True)
    logger.info(f"  Dropped NaNs/Infs → {len(df):,} remaining")

    # 3. Filter out corrupt / negative Flow Duration
    if "Flow Duration" in df.columns:
        neg_count = (df["Flow Duration"] < 0).sum()
        df = df[df["Flow Duration"] >= 0]
        logger.info(f"  Dropped {neg_count:,} corrupt flows with Flow Duration < 0")

    # 4. Remove exact duplicates
    dup_before = len(df)
    df.drop_duplicates(inplace=True)
    logger.info(f"  Dropped {dup_before - len(df):,} exact duplicate flows")

    # 5. Drop Zero-Variance (constant) columns
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    zero_var_cols = [c for c in num_cols if df[c].std() == 0.0]
    if zero_var_cols:
        df.drop(columns=zero_var_cols, inplace=True)
        logger.info(f"  Dropped {len(zero_var_cols)} constant zero-variance features: {zero_var_cols}")

    total_removed = original - len(df)
    logger.success(f"Sanitization complete: removed {total_removed:,} flows ({len(df):,} clean flows remain)")
    return df.reset_index(drop=True)


def balance_dataset(df: pd.DataFrame, benign_ratio: float = 2.0) -> pd.DataFrame:
    """
    Keep 100% of all attack samples.
    Subsample the massive BENIGN class to a balanced ratio (e.g. 2:1 benign-to-attack).
    Prevents models from drowning in 85% normal traffic while preserving diverse attack patterns.
    """
    logger.info("\n" + "=" * 50)
    logger.info("▶ Balancing Class Proportions (Undersampling BENIGN)")
    logger.info("=" * 50)

    attacks = df[df["label_category"] != "BENIGN"]
    benign  = df[df["label_category"] == "BENIGN"]

    n_attacks = len(attacks)
    n_benign_target = min(len(benign), int(n_attacks * benign_ratio))

    logger.info(f"  Total Attacks (100% retained): {n_attacks:,}")
    logger.info(f"  Original BENIGN: {len(benign):,} → Sampling {n_benign_target:,} (Ratio: {benign_ratio}:1)")

    benign_sampled = benign.sample(n=n_benign_target, random_state=settings.random_seed)

    balanced_df = pd.concat([attacks, benign_sampled], ignore_index=True)
    balanced_df = balanced_df.sample(frac=1.0, random_state=settings.random_seed).reset_index(drop=True)

    logger.success(f"Balanced Dataset: {len(balanced_df):,} flows total")
    return balanced_df


def encode_labels(df: pd.DataFrame, le: LabelEncoder) -> pd.DataFrame:
    logger.info("Encoding labels into categories...")
    df["label_category"] = df["Label"].apply(map_label)
    df["label_binary"]   = (df["label_category"] != "BENIGN").astype(int)
    df["label_encoded"]  = le.fit_transform(df["label_category"])

    logger.info("Class distribution:")
    for cls, cnt in df["label_category"].value_counts().items():
        logger.info(f"  {cls:<20} {cnt:>8,}  ({cnt/len(df)*100:.2f}%)")

    df.drop(columns=["Label"], inplace=True)
    return df


def run():
    logger.info("=" * 55)
    logger.info("Starting High-Performance Preprocessing Pipeline")
    logger.info("=" * 55)

    scaler = StandardScaler()
    le     = LabelEncoder()

    # 1. Load raw
    df = load_raw()

    # 2. Clean, filter corrupt flows, and drop zero-variance features
    df = clean_and_filter(df)

    # 3. Encode labels
    df = encode_labels(df, le)

    # 4. Smart balance (keep 100% attacks, 2:1 ratio for BENIGN)
    df = balance_dataset(df, benign_ratio=2.0)

    label_cols = ["label_category", "label_binary", "label_encoded"]
    feature_cols = [c for c in df.columns if c not in label_cols]

    X = df[feature_cols].astype(np.float32)
    y_binary = df["label_binary"].values
    y_multi  = df["label_encoded"].values

    logger.info(f"Selected Features: {X.shape[1]}  Total Samples: {X.shape[0]:,}")

    # 5. Stratified 80/20 Train/Test split across all classes
    logger.info("Splitting dataset (80% Train, 20% Test) with multi-class stratification...")
    X_train, X_test, y_train_b, y_test_b, y_train_m, y_test_m = train_test_split(
        X, y_binary, y_multi,
        test_size=settings.test_size,
        random_state=settings.random_seed,
        stratify=y_multi,
    )

    # 6. Standard Scaling
    logger.info("Normalizing features with StandardScaler...")
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # 7. Save processed arrays
    out = settings.data_processed_dir
    out.mkdir(parents=True, exist_ok=True)

    logger.info("Saving processed datasets to disk...")
    np.save(out / "X_train.npy", X_train_s)
    np.save(out / "X_test.npy",  X_test_s)
    np.save(out / "y_train_binary.npy", y_train_b)
    np.save(out / "y_test_binary.npy",  y_test_b)
    np.save(out / "y_train_multi.npy",  y_train_m)
    np.save(out / "y_test_multi.npy",   y_test_m)

    # Save scaler and label encoder
    with open(out / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(out / "label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)

    # Save metadata
    meta = {
        "n_features":      X.shape[1],
        "feature_columns": feature_cols,
        "class_names":     list(le.classes_),
        "n_train":         len(X_train_s),
        "n_test":          len(X_test_s),
    }
    with open(out / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    logger.success("=" * 55)
    logger.success("✔ Data Preprocessing & Filtering Completed Successfully!")
    logger.info(f"  Features: {meta['n_features']} informative columns")
    logger.info(f"  Training Samples: {len(X_train_s):,}")
    logger.info(f"  Testing Samples : {len(X_test_s):,}")
    logger.info(f"  Classes ({len(meta['class_names'])}): {meta['class_names']}")
    logger.success("=" * 55)


if __name__ == "__main__":
    run()
