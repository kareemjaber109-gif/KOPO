"""
Item 5: DoS raw-label breakdown in Train/Val/Test blocks (FIXED).
Uses class_splits from metadata to infer split boundaries, then reads raw labels from parquets.
"""
import json
import numpy as np
from pathlib import Path
import pandas as pd

CLEAN_DIR = Path("data/processed/clean")

def run():
    print("=" * 70)
    print("ITEM 5: DoS RAW LABEL BREAKDOWN IN TRAIN / VAL / TEST BLOCKS")
    print("=" * 70)

    meta_path = CLEAN_DIR / "metadata.json"
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    class_splits = meta["class_splits"]
    class_names = meta["class_names"]

    print("Computed splits from metadata (class_splits):")
    for cname, splits in class_splits.items():
        t = splits.get("train", 0)
        v = splits.get("val", 0)
        te = splits.get("test", 0)
        total = splits.get("total", t+v+te)
        print(f"  {cname:<15}: Train={t:>8,} | Val={v:>7,} | Test={te:>7,} | Total={total:>8,}")

    # --- Now check raw DoS sub-labels from parquets ---
    print("\n" + "=" * 70)
    print("RAW LABEL ANALYSIS FROM PARQUETS")
    print("=" * 70)

    # Find parquet files
    parquet_dirs = [
        Path("data/raw/flows_parquet"),
        Path("data/raw"),
    ]
    files = []
    for d in parquet_dirs:
        if d.exists():
            files = sorted(d.glob("*.parquet"))
            if files:
                break

    if not files:
        print("No parquet files found. Trying CSV approach...")
        # Try loading from the original split data
        # We know the sequential split is by row order within each class
        # Can't get raw labels without parquets or CSVs
        print("FALLBACK: Reading DoS sub-label mapping from known CIC-IDS2017 structure")
        print("""
  CIC-IDS2017 DoS raw labels:
  - 'DoS Hulk' (most frequent)
  - 'DoS GoldenEye'
  - 'DoS slowloris'
  - 'DoS Slowhttptest'
  - 'Heartbleed' (very rare, often grouped with DoS)
  
  The sequential block split puts last 10% rows of each mapped class into Test.
  Since DoS subtypes appear in different CSV files (different days):
  - Tuesday: Hulk, GoldenEye, Slowloris, Slowhttptest
  - If original row order groups by day, the Test block would be biased
    toward whichever subtype appears at the end of the DoS group.
  
  This likely explains the 67.5% DoS recall on Test: the Test block
  oversamples a harder subtype (slowloris/Slowhttptest) and undersamples
  the easier one (Hulk) that dominates Training.
        """)
        return

    print(f"Found {len(files)} parquet files")

    # Load all labels
    all_labels = []
    for f in files:
        df = pd.read_parquet(f, columns=["Label"])
        all_labels.append(df["Label"].values)
        print(f"  {f.name}: {len(df):,} rows")
    raw_labels = np.concatenate(all_labels)
    total = len(raw_labels)
    print(f"Total rows: {total:,}")

    # Map raw labels to our class labels (same mapping as clean_split.py)
    from src.data.clean_split import map_label
    mapped = np.array([map_label(l) for l in raw_labels])

    # For each mapped class, the split is sequential blocks:
    # train (70%) | gap1 (5%) | val (10%) | gap2 (5%) | test (10%)
    dos_raw_in_split = {}
    for cname in class_names:
        cls_indices = np.where(mapped == cname)[0]
        n_cls = len(cls_indices)
        if n_cls == 0:
            continue

        splits = class_splits[cname]
        n_train = splits.get("train", 0)
        n_gap1  = splits.get("gap1", 0)
        n_val   = splits.get("val", 0)
        n_gap2  = splits.get("gap2", 0)
        n_test  = splits.get("test", 0)

        # Sequential assignment
        train_end   = n_train
        gap1_end    = train_end + n_gap1
        val_end     = gap1_end  + n_val
        gap2_end    = val_end   + n_gap2

        train_idx = cls_indices[:train_end]
        val_idx   = cls_indices[gap1_end:val_end]
        test_idx  = cls_indices[gap2_end:gap2_end + n_test]

        # Count raw labels in each split
        raw_train = raw_labels[train_idx]
        raw_val   = raw_labels[val_idx]
        raw_test  = raw_labels[test_idx]

        unique_raw = set(raw_labels[cls_indices])
        for raw_lbl in sorted(unique_raw):
            key = (cname, raw_lbl)
            dos_raw_in_split[key] = {
                "Train": int(np.sum(raw_train == raw_lbl)),
                "Val":   int(np.sum(raw_val == raw_lbl)),
                "Test":  int(np.sum(raw_test == raw_lbl)),
            }

    print(f"\n{'Mapped Class':<15} {'Raw Label':<30} {'Train':>8} {'Val':>8} {'Test':>8}")
    print("-" * 75)
    for (cname, raw_lbl), counts in sorted(dos_raw_in_split.items()):
        total_raw = sum(counts.values())
        if total_raw > 0:
            print(f"{cname:<15} {raw_lbl:<30} {counts['Train']:>8,} {counts['Val']:>8,} {counts['Test']:>8,}")

    # Focus on DoS
    print("\n--- DoS SUBTYPE FOCUS ---")
    dos_entries = {k: v for k, v in dos_raw_in_split.items() if k[0] == "DoS"}
    for (cname, raw_lbl), counts in sorted(dos_entries.items()):
        total_raw = sum(counts.values())
        if total_raw > 0:
            test_pct = counts['Test'] / total_raw * 100 if total_raw > 0 else 0
            print(f"  {raw_lbl:<30} Train={counts['Train']:>7,}  Val={counts['Val']:>6,}  Test={counts['Test']:>6,}  (Test={test_pct:.1f}%)")

    print("\n--- ANALYSIS ---")
    print("If a DoS subtype is concentrated at the end of the DoS group by row order,")
    print("the Test block will oversample it. Check if Test has disproportionate")
    print("slowloris/Slowhttptest (harder) vs Hulk (easier).")


if __name__ == "__main__":
    run()
