r"""Step 1 - build the strict one-class dataset for KOPO anomaly detection.

Run from the repo root (PowerShell):

    python -m src.data.prepare_unsw_nb15 --unsw-dir "C:\Users\rzqm7\OneDrive\Desktop\datasets\CIC-UNSW-NB15" --cicids-path data\raw\<folder-with-CICIDS2017-csvs> --inspect

``--inspect`` only prints columns / label counts / feature matching and writes
nothing. Run it first, check the report, then run again without ``--inspect``.

What it does
  1. Loads Data.csv + Label.csv (CIC-UNSW-NB15) and, optionally, CICIDS2017 Benign
     flows (a CSV file or a folder of CSVs that still have their label column).
  2. Matches columns by canonical name (short CICFlowMeter names such as
     "Tot Fwd Pkts" <-> "Total Fwd Packets"), drops identifier columns,
     Protocol and Destination Port, and keeps the common behavioural features.
  3. Drops NaN/inf rows, label-conflicting rows and duplicates.
  4. Benign: 80/10/10 train/val/test (per source). Attacks: 50/50 val/test per
     category. Attacks never touch train.
  5. Fits AnomalyPreprocessor (signed log1p, p0.1/p99.9 clip, StandardScaler)
     on Benign-train ONLY and transforms every split with it.
  6. Writes train/val/test .npz + summary.json to --out-dir and
     scaler_anomaly.pkl + feature_names.json to --model-dir.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from src.ml.anomaly.preprocessing import (
    NON_BEHAVIORAL_KEYS,
    PORT_KEYS,
    AnomalyPreprocessor,
    canon_key,
    display_name,
)

BENIGN_TOKENS = {"benign", "normal", "0", "0.0", "false"}
INVALID_LABELS = {"nan", "", "unknown"}
LABEL_KEYS = {"label", "labels", "attack", "attackcat", "attackcategory",
              "class", "category", "binarylabel", "target"}


def log(*a) -> None:
    print(*a, flush=True)


def _strip_cols(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(c).strip() for c in df.columns]
    return df


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _find_file(folder: Path, name: str) -> Path:
    for p in folder.iterdir():
        if p.name.lower() == name.lower():
            return p
    raise FileNotFoundError(f"{name} not found in {folder}")


def derive_category(lab: pd.DataFrame) -> tuple[pd.Series, str]:
    """Return a per-row category Series ('Benign' or the attack name)."""
    lab = _strip_cols(lab.copy())
    cands = [c for c in lab.columns if not c.lower().startswith("unnamed")]
    if not cands:
        raise ValueError("Label.csv has no usable column")
    text = [c for c in cands if not pd.api.types.is_numeric_dtype(lab[c])]
    pool = text or cands
    pool = [c for c in pool if lab[c].nunique(dropna=True) <= 50] or pool
    col = max(pool, key=lambda c: lab[c].nunique(dropna=True))
    s = lab[col]
    note = f"label column used: {col!r}"
    if pd.api.types.is_numeric_dtype(s):
        vals = set(s.dropna().unique().tolist())
        if vals <= {0, 1}:
            cat = s.map(lambda v: "Unknown" if pd.isna(v) else ("Benign" if v == 0 else "Attack"))
            note += " (numeric 0/1 -> per-category evaluation unavailable)"
        else:
            cat = s.map(lambda v: "Unknown" if pd.isna(v) else ("Benign" if v == 0 else f"class_{int(v)}"))
            note += " (numeric ids, assuming 0 = Benign)"
    else:
        st = s.astype(str).str.strip()
        cat = st.where(~st.str.lower().isin(BENIGN_TOKENS), "Benign")
    return cat.reset_index(drop=True), note


def load_unsw(unsw_dir: str) -> tuple[pd.DataFrame, pd.Series, str]:
    d = Path(unsw_dir)
    if not d.is_dir():
        raise FileNotFoundError(f"--unsw-dir is not a folder: {d}")
    X = _strip_cols(pd.read_csv(_find_file(d, "Data.csv"), low_memory=False))
    lab_path = _find_file(d, "Label.csv")
    lab = pd.read_csv(lab_path, low_memory=False)
    if len(lab) == len(X) - 1 and lab.shape[1] == 1:      # Label.csv without header
        lab = pd.read_csv(lab_path, header=None, low_memory=False)
    if len(lab) != len(X):
        raise ValueError(f"Data.csv has {len(X):,} rows but Label.csv has {len(lab):,}")
    cat, note = derive_category(lab)
    return X, cat, note


def _cicids_files(path: str) -> list[Path]:
    p = Path(path)
    if p.is_dir():
        files = sorted(list(p.glob("*.csv")) + list(p.glob("*.parquet")))
    else:
        files = [p]
    if not files:
        raise FileNotFoundError(f"no CSV or Parquet files found in {p}")
    return files


def _read_cicids(f: Path, **kw) -> pd.DataFrame:
    if f.suffix.lower() == ".parquet":
        return _strip_cols(pd.read_parquet(f))
    return _strip_cols(pd.read_csv(f, low_memory=False, encoding="latin-1", **kw))


def _label_col(df: pd.DataFrame, where: str) -> str:
    col = next((c for c in df.columns if canon_key(c) in LABEL_KEYS), None)
    if col is None:
        raise ValueError(f"{where}: no label column found; columns start with {list(df.columns)[:8]}")
    return col


def load_cicids_benign(path: str, target: int, rng: np.random.Generator) -> pd.DataFrame:
    """Benign rows only, capped per file so every day/file is represented."""
    files = _cicids_files(path)
    cap = max(2000, int(2 * target / len(files)))
    parts = []
    for f in files:
        df = _read_cicids(f)
        lc = _label_col(df, f.name)
        mask = df[lc].astype(str).str.strip().str.lower().isin({"benign", "normal"})
        ben = df.loc[mask].drop(columns=[lc])
        if len(ben) > cap:
            ben = ben.sample(cap, random_state=int(rng.integers(2**31 - 1)))
        log(f"[cicids] {f.name}: {int(mask.sum()):,} benign rows, kept {len(ben):,}")
        parts.append(ben)
    return pd.concat(parts, ignore_index=True)


# --------------------------------------------------------------------------- #
# Feature matching
# --------------------------------------------------------------------------- #
@dataclass
class Selection:
    keys: list[str]
    features: list[str]            # display names, model order
    u_map: dict[str, str]          # key -> original UNSW column
    c_map: dict[str, str]          # key -> original CICIDS column
    unsw_only: list[str]
    cicids_only: list[str]
    excluded: list[str]


def select_features(unsw_cols, cic_cols, keep_port: bool) -> Selection:
    excluded_keys = set(NON_BEHAVIORAL_KEYS) | (set() if keep_port else PORT_KEYS)
    excluded: list[str] = []

    def keymap(cols):
        m: dict[str, str] = {}
        for c in cols:
            k = canon_key(c)
            if k in excluded_keys or k.startswith("unnamed"):
                excluded.append(str(c))
                continue
            m.setdefault(k, c)
        return m

    u = keymap(unsw_cols)
    if cic_cols is None:
        keys = list(u)
        c: dict[str, str] = {}
        only_u, only_c = [], []
    else:
        c = keymap(cic_cols)
        keys = [k for k in u if k in c]
        only_u = [u[k] for k in u if k not in c]
        only_c = [c[k] for k in c if k not in u]
    feats = [str(c[k]).strip() if k in c else display_name(u[k]) for k in keys]
    return Selection(keys, feats, u, c, only_u, only_c, sorted(set(excluded)))


def to_frame(df: pd.DataFrame, keymap: dict[str, str], sel: Selection) -> pd.DataFrame:
    return pd.DataFrame({f: pd.to_numeric(df[keymap[k]], errors="coerce").astype("float64").to_numpy()
                         for k, f in zip(sel.keys, sel.features)})


# --------------------------------------------------------------------------- #
# Cleaning + splitting
# --------------------------------------------------------------------------- #
def clean_dedup(df: pd.DataFrame, features: list[str], source: str) -> tuple[pd.DataFrame, dict]:
    st = {"raw": int(len(df))}
    finite = np.isfinite(df[features].to_numpy(np.float64)).all(axis=1)
    st["dropped_nan_inf"] = int((~finite).sum())
    df = df.loc[finite].reset_index(drop=True)

    h = pd.util.hash_pandas_object(df[features], index=False)
    att = pd.Series((df["category"] != "Benign").to_numpy())
    conflict = (att.groupby(h.to_numpy()).transform("nunique") > 1).to_numpy()
    st["dropped_label_conflicts"] = int(conflict.sum())
    df, h = df.loc[~conflict], h[~conflict]

    dup = h.duplicated().to_numpy()
    st["dropped_duplicates"] = int(dup.sum())
    df = df.loc[~dup].copy()
    df["_h"] = h[~dup].to_numpy()
    df["source"] = source
    st["kept"] = int(len(df))
    return df.reset_index(drop=True), st


def split_benign(df: pd.DataFrame, rng: np.random.Generator):
    tr, va, te = [], [], []
    for _, g in df.groupby("source", sort=False):
        g = g.iloc[rng.permutation(len(g))]
        n_tr, n_va = int(round(len(g) * 0.8)), int(round(len(g) * 0.1))
        tr.append(g.iloc[:n_tr])
        va.append(g.iloc[n_tr:n_tr + n_va])
        te.append(g.iloc[n_tr + n_va:])
    return pd.concat(tr), pd.concat(va), pd.concat(te)


def split_attacks(df: pd.DataFrame, rng: np.random.Generator):
    va, te = [], []
    for _, g in df.groupby("category", sort=True):
        g = g.iloc[rng.permutation(len(g))]
        n_va = len(g) // 2
        va.append(g.iloc[:n_va])
        te.append(g.iloc[n_va:])
    return pd.concat(va), pd.concat(te)


def _strs(s: pd.Series) -> np.ndarray:
    return np.asarray(s.astype(str).to_numpy(), dtype=str)


# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--unsw-dir", required=True, help="folder with Data.csv and Label.csv")
    ap.add_argument("--cicids-path", default=None,
                    help="CICIDS2017 CSV file or folder of CSVs (with label column). Omit = UNSW only")
    ap.add_argument("--out-dir", default="data/processed/unsw")
    ap.add_argument("--model-dir", default="data/models/anomaly")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--cicids-benign-ratio", type=float, default=1.0,
                    help="CICIDS Benign rows = ratio x UNSW Benign rows (default 1.0 = balanced)")
    ap.add_argument("--keep-dst-port", action="store_true", help="keep Destination Port as a feature")
    ap.add_argument("--max-nan-col-frac", type=float, default=0.5,
                    help="drop a feature if more than this fraction of its values is NaN/inf/non-numeric")
    ap.add_argument("--inspect", action="store_true", help="print the report and exit; writes nothing")
    return ap.parse_args(argv)


def _print_selection(sel: Selection) -> None:
    log(f"[features] common behavioural features: {len(sel.features)}")
    log(f"[features] excluded by rule (ids/Protocol/Dst Port/label): {sel.excluded}")
    if sel.unsw_only:
        log(f"[features] only in UNSW  ({len(sel.unsw_only)}): {sel.unsw_only}")
    if sel.cicids_only:
        log(f"[features] only in CICIDS ({len(sel.cicids_only)}): {sel.cicids_only}")
    if sel.unsw_only or sel.cicids_only:
        log("           ^ if a pair here is the SAME feature with different spelling, "
            "add it to _SHORT_TO_2017_PAIRS in src/ml/anomaly/preprocessing.py")


def main(argv=None) -> int:
    a = parse_args(argv)
    rng = np.random.default_rng(a.seed)

    X_u, cat_u, note = load_unsw(a.unsw_dir)
    log(f"[unsw] Data.csv: {len(X_u):,} rows x {X_u.shape[1]} columns | {note}")
    log(f"[unsw] label counts: {cat_u.value_counts().to_dict()}")
    n_benign_raw = int((cat_u == "Benign").sum())

    if a.inspect:
        cic_cols = None
        if a.cicids_path:
            cic_cols = list(_read_cicids(_cicids_files(a.cicids_path)[0], nrows=5).columns)
            _label_col(pd.DataFrame(columns=cic_cols), "CICIDS header")
            cic_cols = [c for c in cic_cols if canon_key(c) not in LABEL_KEYS]
        log("[unsw] columns:", list(X_u.columns))
        _print_selection(select_features(X_u.columns, cic_cols, a.keep_dst_port))
        log("--inspect: nothing written.")
        return 0

    cic_raw = None
    if a.cicids_path:
        cic_raw = load_cicids_benign(a.cicids_path, int(a.cicids_benign_ratio * n_benign_raw), rng)
    else:
        log("WARNING: no --cicids-path -> UNSW-only Benign. Expect a domain-shift false-positive "
            "problem on CICIDS2017-like traffic.")

    sel = select_features(X_u.columns, None if cic_raw is None else cic_raw.columns, a.keep_dst_port)
    _print_selection(sel)

    unsw_f = to_frame(X_u, sel.u_map, sel)
    cic_f = to_frame(cic_raw, sel.c_map, sel) if cic_raw is not None else None

    def nan_frac(df):
        return pd.Series(np.where(np.isfinite(df.to_numpy()), 0.0, 1.0).mean(axis=0), index=df.columns)
    bad = nan_frac(unsw_f)
    if cic_f is not None:
        bad = np.maximum(bad, nan_frac(cic_f))
    bad_cols = bad[bad > a.max_nan_col_frac].index.tolist()
    features = [f for f in sel.features if f not in bad_cols]
    if bad_cols:
        log(f"[features] dropped (>{a.max_nan_col_frac:.0%} NaN/inf/non-numeric): {bad_cols}")

    unsw_f = unsw_f[features].copy()
    unsw_f["category"] = cat_u.to_numpy()
    unsw_f = unsw_f[~unsw_f["category"].str.lower().isin(INVALID_LABELS)]
    unsw_clean, st_u = clean_dedup(unsw_f.reset_index(drop=True), features, "unsw")
    log(f"[clean] unsw: {st_u}")

    benign_u = unsw_clean[unsw_clean["category"] == "Benign"]
    attacks = unsw_clean[unsw_clean["category"] != "Benign"]
    parts, st_c = [benign_u], None
    if cic_f is not None:
        cic_f = cic_f[features].copy()
        cic_f["category"] = "Benign"
        cic_clean, st_c = clean_dedup(cic_f, features, "cicids2017")
        log(f"[clean] cicids2017: {st_c}")
        n_c = min(len(cic_clean), int(round(a.cicids_benign_ratio * len(benign_u))))
        parts.append(cic_clean.sample(n_c, random_state=a.seed))
    benign = pd.concat(parts, ignore_index=True)

    b_tr, b_va, b_te = split_benign(benign, rng)
    a_va, a_te = split_attacks(attacks, rng)
    val = pd.concat([b_va, a_va], ignore_index=True)
    test = pd.concat([b_te, a_te], ignore_index=True)
    train = b_tr.reset_index(drop=True)

    # No flow may appear in two splits.
    for n1, d1, n2, d2 in [("train", train, "val", val), ("train", train, "test", test), ("val", val, "test", test)]:
        overlap = np.intersect1d(d1["_h"].to_numpy(), d2["_h"].to_numpy())
        if len(overlap):
            raise RuntimeError(f"{len(overlap)} identical flows found in both {n1} and {n2}")

    # Everything below is fitted on Benign-train only.
    pre = AnomalyPreprocessor().fit(train, features)
    log(f"[preprocess] {len(pre.features)} features kept, zero-variance dropped: {pre.dropped_zero_variance}")

    out, mdir = Path(a.out_dir), Path(a.model_dir)
    out.mkdir(parents=True, exist_ok=True)
    pre.save(mdir)

    def pack(df: pd.DataFrame, with_labels: bool) -> dict:
        d = {"X": pre.transform(df[features]), "source": _strs(df["source"])}
        if with_labels:
            d["y"] = (df["category"] != "Benign").to_numpy(np.int8)
            d["category"] = _strs(df["category"])
        return d

    np.savez_compressed(out / "train.npz", **pack(train, False))
    np.savez_compressed(out / "val.npz", **pack(val, True))
    np.savez_compressed(out / "test.npz", **pack(test, True))

    def describe(df: pd.DataFrame) -> dict:
        return {"rows": int(len(df)),
                "benign": int((df["category"] == "Benign").sum()),
                "attack": int((df["category"] != "Benign").sum()),
                "by_source": df["source"].value_counts().to_dict(),
                "by_category": df["category"].value_counts().to_dict()}

    summary = {
        "config": vars(a),
        "label_note": note,
        "raw_unsw_label_counts": cat_u.value_counts().to_dict(),
        "cleaning": {"unsw": st_u, "cicids2017": st_c},
        "features": {"used": pre.features, "n": len(pre.features),
                     "dropped_zero_variance": pre.dropped_zero_variance,
                     "dropped_mostly_nan": bad_cols,
                     "unsw_only_columns": sel.unsw_only,
                     "cicids_only_columns": sel.cicids_only,
                     "excluded_by_rule": sel.excluded},
        "splits": {"train": describe(train), "val": describe(val), "test": describe(test)},
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    log("\n=== DONE ===")
    for name, d in summary["splits"].items():
        log(f"{name:5s}: {d['rows']:>8,} rows | benign {d['benign']:>8,} | attack {d['attack']:>7,} | {d['by_source']}")
    log(f"arrays   -> {out}")
    log(f"scaler   -> {mdir / 'scaler_anomaly.pkl'}  (+ feature_names.json)")
    log(f"summary  -> {out / 'summary.json'}  <- paste this file back to Claude")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
