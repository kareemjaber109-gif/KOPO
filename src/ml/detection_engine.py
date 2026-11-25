import os
import json
import pickle
from pathlib import Path
from typing import Optional
import numpy as np
from src.utils.config import settings
from src.utils.logger import logger

ATTACK_SEVERITY = {
    "BENIGN":             0,
    # DDoS & Floods
    "SYN_FLOOD":          5,
    "UDP_FLOOD":          4,
    "ICMP_FLOOD":         4,
    "DNS_AMPLIFICATION":  5,
    "NTP_AMPLIFICATION":  5,
    "SMURF":              4,
    "DDoS":               5,
    "DDOS":               5,
    # DoS Attacks
    "HTTP_FLOOD":         4,
    "SLOWLORIS":          4,
    "SLOWHTTPTEST":       3,
    "PING_OF_DEATH":      4,
    "TEARDROP":           4,
    "LAND_ATTACK":        4,
    "DoS":                4,
    "DOS":                4,
    # Recon & Scans
    "PORT_SCAN":          2,
    "SYN_SCAN":           2,
    "NULL_SCAN":          2,
    "FIN_SCAN":           2,
    "XMAS_SCAN":          3,
    "PortScan":           2,
    # Brute Force
    "BRUTE_FORCE_SSH":    3,
    "BRUTE_FORCE_FTP":    3,
    "BRUTE_FORCE_WEB":    3,
    "SSH_PATATOR":        3,
    "FTP_PATATOR":        3,
    "BruteForce":         3,
    # Web Exploits
    "SQL_INJECTION":      4,
    "XSS":                3,
    "WEB_ATTACK":         4,
    "HEARTBLEED":         5,
    "PHISHING":           3,
    "WebAttack":          4,
    # Malware & C2
    "BOTNET":             4,
    "RANSOMWARE":         5,
    "C2_BEACON":          4,
    "CRYPTOMINING":       3,
    "Bot":                4,
    # Zero-Day & Infiltration
    "DATA_EXFILTRATION":  5,
    "ZERO_DAY_EXPLOIT":   5,
    "EMAIL_SPAM":         2,
    "Infiltration":       5,
    "ANOMALY":            3,
    "ATTACK":             3,
}

SEVERITY_LABELS = {
    0: "None",
    1: "Info",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}


ATTACK_CATEGORY_MAP = {
    "BENIGN": "Normal Traffic",
    # DoS Attacks (Denial of Service - Single Source Floods & Slow Attacks)
    "HTTP_FLOOD": "DoS Attacks",
    "SLOWLORIS": "DoS Attacks",
    "SLOWHTTPTEST": "DoS Attacks",
    "PING_OF_DEATH": "DoS Attacks",
    "TEARDROP": "DoS Attacks",
    "LAND_ATTACK": "DoS Attacks",
    "DoS": "DoS Attacks",
    "DOS": "DoS Attacks",
    # DDoS & Floods (Distributed Amplifications & Massive Volumetric)
    "SYN_FLOOD": "DDoS & Floods",
    "UDP_FLOOD": "DDoS & Floods",
    "ICMP_FLOOD": "DDoS & Floods",
    "DNS_AMPLIFICATION": "DDoS & Floods",
    "NTP_AMPLIFICATION": "DDoS & Floods",
    "SMURF": "DDoS & Floods",
    "DDoS": "DDoS & Floods",
    "DDOS": "DDoS & Floods",
    # Recon & Scans
    "PORT_SCAN": "Recon & Scans",
    "SYN_SCAN": "Recon & Scans",
    "NULL_SCAN": "Recon & Scans",
    "FIN_SCAN": "Recon & Scans",
    "XMAS_SCAN": "Recon & Scans",
    "PortScan": "Recon & Scans",
    # Brute Force
    "BRUTE_FORCE_SSH": "Brute Force",
    "BRUTE_FORCE_FTP": "Brute Force",
    "BRUTE_FORCE_WEB": "Brute Force",
    "SSH_PATATOR": "Brute Force",
    "FTP_PATATOR": "Brute Force",
    "BruteForce": "Brute Force",
    # Web Exploits
    "SQL_INJECTION": "Web Exploits",
    "XSS": "Web Exploits",
    "WEB_ATTACK": "Web Exploits",
    "HEARTBLEED": "Web Exploits",
    "PHISHING": "Web Exploits",
    "WebAttack": "Web Exploits",
    # Malware & C2
    "BOTNET": "Malware & C2",
    "RANSOMWARE": "Malware & C2",
    "C2_BEACON": "Malware & C2",
    "CRYPTOMINING": "Malware & C2",
    "Bot": "Malware & C2",
    # Zero-Day & Infil
    "DATA_EXFILTRATION": "Zero-Day & Infil",
    "ZERO_DAY_EXPLOIT": "Zero-Day & Infil",
    "EMAIL_SPAM": "Zero-Day & Infil",
    "Infiltration": "Zero-Day & Infil",
    "ANOMALY": "Behavioral Anomaly"
}


class DetectionEngine:

    _instance: Optional["DetectionEngine"] = None

    def __init__(self):
        self.scaler        = None
        self.rf_model      = None
        self.xgb_model     = None
        self.lstm_model    = None
        self.iso_model     = None
        self.anomaly_ensemble = None
        self.anomaly_preprocessor = None
        self.feature_cols  = []
        self.class_names   = []
        self.active_run_id = "default"
        self.data_origin   = "real"
        self.active_manifest = {}
        self._loaded       = False

    @classmethod
    def get_instance(cls) -> "DetectionEngine":
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.load()
        return cls._instance

    def load(self):
        import os
        processed  = settings.data_processed_dir
        base_models_dir = settings.models_dir

        # Read active run pointer from current.json (Windows-safe pointer, replaces symlinks)
        current_config = base_models_dir / "current.json"
        active_models_dir = base_models_dir
        self.data_origin = "real"
        self.active_run_id = "default"

        if current_config.exists():
            try:
                with open(current_config, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                run_dir_str = cfg.get("run_dir", "")
                if run_dir_str:
                    cand_dir = Path(run_dir_str)
                    if not cand_dir.is_absolute():
                        cand_dir = Path.cwd() / cand_dir
                    if cand_dir.exists():
                        active_models_dir = cand_dir
                self.data_origin = cfg.get("data_origin", "synthetic")
                self.active_run_id = cfg.get("active_run_id", "quarantine_synthetic_v0")
                logger.info(f"Loaded active model pointer: '{self.active_run_id}' [origin: {self.data_origin}] from current.json")
            except Exception as e:
                logger.warning(f"Failed to read current.json: {e}")

        manifest_path = active_models_dir / "manifest.json"
        if manifest_path.exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    self.active_manifest = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to read active manifest.json: {e}")

        # Check independent anomaly model manifest
        anomaly_dir = active_models_dir / "anomaly"
        if not anomaly_dir.exists():
            anomaly_dir = base_models_dir / "anomaly"

        self.anomaly_manifest = None
        self.anomaly_origin = "real"
        self.anomaly_ready = False
        if (anomaly_dir / "manifest.json").exists():
            try:
                with open(anomaly_dir / "manifest.json", "r", encoding="utf-8") as f:
                    self.anomaly_manifest = json.load(f)
                    self.anomaly_origin = self.anomaly_manifest.get("data_origin", "real")
            except Exception as e:
                logger.warning(f"Failed to read anomaly manifest: {e}")

        # Enforce Safety Guard on Synthetic Models (Default mode is STRICT / production)
        is_demo_mode = os.environ.get("KOPO_DEMO_MODE", "false").lower() in ["true", "1", "yes"]
        load_supervised = True
        if self.data_origin == "synthetic":
            if is_demo_mode:
                logger.warning("DEMO NOTICE: Loading quarantined synthetic models for UI demonstration. Production benchmark requires real dataset run.")
            else:
                logger.warning("STRICT PRODUCTION MODE: Synthetic supervised models detected in current.json. Refusing to serve synthetic weights in production mode.")
                load_supervised = False

        scaler_path = active_models_dir / "scaler.pkl"
        if not scaler_path.exists():
            scaler_path = base_models_dir / "scaler.pkl"
        if not scaler_path.exists():
            scaler_path = processed / "scaler.pkl"

        meta_path = active_models_dir / "manifest.json"
        if not meta_path.exists():
            meta_path = processed / "metadata.json"

        if not scaler_path.exists() or not meta_path.exists():
            logger.warning("Scaler or metadata missing — run preprocessor first")
            return

        with open(scaler_path, "rb") as f:
            self.scaler = pickle.load(f)

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.feature_cols = meta.get("feature_columns", [])
        self.class_names  = meta.get("class_names", [])

        # Load Supervised models only when allowed (demo mode or verified real benchmark run)
        if load_supervised:
            rf_path = active_models_dir / "random_forest.pkl"
            if not rf_path.exists():
                rf_path = base_models_dir / "random_forest.pkl"
            if rf_path.exists():
                try:
                    from src.ml.models.random_forest import RFModel
                    self.rf_model = RFModel().load(rf_path)
                    if not getattr(self.rf_model, "class_names", None):
                        self.rf_model.class_names = self.class_names
                    logger.info("  Random Forest    : loaded")
                except Exception as e:
                    logger.warning(f"  Random Forest load failed: {e}")

            xgb_path = active_models_dir / "xgboost.pkl"
            if not xgb_path.exists():
                xgb_path = base_models_dir / "xgboost.pkl"
            if xgb_path.exists():
                try:
                    from src.ml.models.xgboost_model import XGBModel
                    self.xgb_model = XGBModel.load(xgb_path)
                    if not getattr(self.xgb_model, "class_names", None):
                        self.xgb_model.class_names = self.class_names
                    logger.info(f"  XGBoost          : loaded ({len(self.xgb_model.class_names)} classes)")
                except Exception as e:
                    logger.warning(f"  XGBoost load failed: {e}")

            lstm_path = active_models_dir / "lstm.pt"
            if not lstm_path.exists():
                lstm_path = base_models_dir / "lstm.pt"
            if lstm_path.exists():
                try:
                    from src.ml.models.lstm_model import LSTMModel
                    self.lstm_model = LSTMModel.load(lstm_path)
                    logger.info("  LSTM             : loaded")
                except Exception as e:
                    logger.warning(f"  LSTM load failed: {e}")

            iso_path = active_models_dir / "isolation_forest.pkl"
            if not iso_path.exists():
                iso_path = base_models_dir / "isolation_forest.pkl"
            if iso_path.exists():
                try:
                    from src.ml.models.isolation_forest import IsolationForestModel
                    self.iso_model = IsolationForestModel.load(iso_path)
                    logger.info("  Isolation Forest : loaded")
                except Exception as e:
                    logger.warning(f"  Isolation Forest load failed: {e}")

        # Load Anomaly Ensemble independently (loads in strict mode if data_origin == 'real')
        if anomaly_dir.exists() and (anomaly_dir / "feature_names.json").exists():
            can_load_anomaly = (self.anomaly_origin == "real") or is_demo_mode
            if can_load_anomaly:
                try:
                    from src.ml.anomaly.preprocessing import AnomalyPreprocessor
                    from src.ml.anomaly.anomaly_ensemble import AnomalyEnsemble

                    self.anomaly_preprocessor = AnomalyPreprocessor.load(anomaly_dir)
                    self.anomaly_ensemble = AnomalyEnsemble.load(anomaly_dir)
                    self.anomaly_ready = True
                    logger.info(f"  Anomaly Ensemble : loaded [origin: {self.anomaly_origin}] (threshold={self.anomaly_ensemble.threshold:.4f})")
                except Exception as e:
                    logger.warning(f"  Anomaly Ensemble load failed: {e}")

        self._loaded = bool(load_supervised or self.anomaly_ready)
        n = sum([
            self.rf_model   is not None,
            self.xgb_model  is not None,
            self.lstm_model is not None,
            self.iso_model  is not None,
        ])
        logger.success(f"Detection Engine ready — {n}/4 models loaded")

    @staticmethod
    def _complete_partial_features(flow: dict) -> dict:
        """
        Intelligently complete missing flow metrics when a partial feature dictionary is supplied.
        Derives byte totals, rates, headers, subflows, and timing intervals so that supervised
        classifiers (XGBoost, RF, LSTM) and Anomaly models have a consistent, coherent representation.
        """
        f = dict(flow)
        fwd = float(f.get("Total Fwd Packets", f.get("Tot Fwd Pkts", 1)))
        bwd = float(f.get("Total Backward Packets", f.get("Tot Bwd Pkts", 0)))
        dur = float(f.get("Flow Duration", 1000))
        dur_sec = max(dur / 1e6, 1e-6)
        fwd_max = float(f.get("Fwd Packet Length Max", f.get("Fwd Pkt Len Max", 0)))
        avg_pkt = float(f.get("Avg Packet Size", f.get("Average Packet Size", fwd_max)))

        # 1. Total Bytes
        if "Fwd Packets Length Total" not in f and "Total Length of Fwd Packets" not in f:
            total_fwd_bytes = fwd * avg_pkt
            f["Fwd Packets Length Total"] = total_fwd_bytes
            f["Total Length of Fwd Packets"] = total_fwd_bytes
        else:
            total_fwd_bytes = float(f.get("Fwd Packets Length Total", f.get("Total Length of Fwd Packets", 0)))

        if "Bwd Packets Length Total" not in f and "Total Length of Bwd Packets" not in f:
            total_bwd_bytes = bwd * (60.0 if bwd else 0.0)
            f["Bwd Packets Length Total"] = total_bwd_bytes
            f["Total Length of Bwd Packets"] = total_bwd_bytes
        else:
            total_bwd_bytes = float(f.get("Bwd Packets Length Total", f.get("Total Length of Bwd Packets", 0)))

        # 2. Rates
        if "Flow Bytes/s" not in f and "Flow Byts/s" not in f:
            f["Flow Bytes/s"] = (total_fwd_bytes + total_bwd_bytes) / dur_sec
        if "Flow Packets/s" not in f and "Flow Pkts/s" not in f:
            f["Flow Packets/s"] = (fwd + bwd) / dur_sec

        # 3. Packet Length Statistics
        if "Fwd Packet Length Mean" not in f:
            f["Fwd Packet Length Mean"] = avg_pkt
        if "Packet Length Mean" not in f:
            f["Packet Length Mean"] = (total_fwd_bytes + total_bwd_bytes) / max(1.0, fwd + bwd)
        if "Packet Length Max" not in f:
            f["Packet Length Max"] = fwd_max
        if "Avg Fwd Segment Size" not in f:
            f["Avg Fwd Segment Size"] = avg_pkt
        if "Average Packet Size" not in f:
            f["Average Packet Size"] = avg_pkt
        if "Avg Packet Size" not in f:
            f["Avg Packet Size"] = avg_pkt

        # 4. Header Lengths
        proto = int(f.get("Protocol", 6))
        hdr_size = 8.0 if proto == 17 else 20.0
        if "Fwd Header Length" not in f:
            f["Fwd Header Length"] = fwd * hdr_size
        if "Bwd Header Length" not in f:
            f["Bwd Header Length"] = bwd * hdr_size

        # 5. Subflow Metrics
        if "Subflow Fwd Packets" not in f:
            f["Subflow Fwd Packets"] = fwd
        if "Subflow Fwd Bytes" not in f:
            f["Subflow Fwd Bytes"] = total_fwd_bytes
        if "Subflow Bwd Packets" not in f:
            f["Subflow Bwd Packets"] = bwd
        if "Subflow Bwd Bytes" not in f:
            f["Subflow Bwd Bytes"] = total_bwd_bytes

        # 6. Inter-Arrival Times (IAT)
        if "Flow IAT Mean" not in f:
            f["Flow IAT Mean"] = dur / max(1.0, fwd + bwd)
        if "Fwd IAT Mean" not in f:
            f["Fwd IAT Mean"] = dur / max(1.0, fwd)
        if "Fwd IAT Total" not in f:
            f["Fwd IAT Total"] = dur

        # 7. TCP Segment Minimums & Window Sizes
        hdr_min = 20.0 if proto == 6 else 8.0
        f["Fwd Seg Size Min"] = hdr_min
        f["min_seg_size_forward"] = hdr_min
        if "Init Fwd Win Bytes" not in f and "Init_Win_bytes_forward" not in f:
            f["Init Fwd Win Bytes"] = 29200.0 if proto == 6 else -1.0
            f["Init_Win_bytes_forward"] = 29200.0 if proto == 6 else -1.0
        if "Init Bwd Win Bytes" not in f and "Init_Win_bytes_backward" not in f:
            f["Init Bwd Win Bytes"] = 227.0 if (bwd > 0 and proto == 6) else -1.0
            f["Init_Win_bytes_backward"] = 227.0 if (bwd > 0 and proto == 6) else -1.0
        f["Fwd Act Data Packets"] = max(fwd - 1.0, 0.0)
        f["act_data_pkt_fwd"] = max(fwd - 1.0, 0.0)

        # 8. Destination Port Inference (Critical for model classification!)
        if "Destination Port" not in f and "port" not in f:
            if proto == 17:
                f["Destination Port"] = 53.0
            elif proto == 1:
                f["Destination Port"] = 0.0
            elif avg_pkt == 0 and float(f.get("SYN Flag Count", 0)) > 0:
                f["Destination Port"] = 80.0
            elif dur > 5_000_000 and 100 <= avg_pkt <= 500 and (fwd >= 100 or bwd >= 50):
                # SSH / FTP Brute Force signature: sustained connection, moderate packet sizes
                f["Destination Port"] = 22.0
            elif dur > 20_000_000 and avg_pkt <= 50 and proto == 6:
                # Slowloris / Slowhttptest
                f["Destination Port"] = 80.0
            elif avg_pkt >= 800 and fwd >= 2000:
                # HTTP DoS / Flood
                f["Destination Port"] = 80.0
            elif avg_pkt >= 500 and fwd <= 300 and dur <= 10_000_000:
                # Web Attack (SQLi / XSS)
                f["Destination Port"] = 80.0
            elif dur >= 50_000_000 and (bwd > fwd * 1.5 or total_bwd_bytes > total_fwd_bytes * 2):
                # Ransomware / Data Exfil
                f["Destination Port"] = 445.0
            elif dur >= 100_000_000:
                # Cryptomining
                f["Destination Port"] = 3333.0
            else:
                f["Destination Port"] = 80.0
        elif "port" in f and "Destination Port" not in f:
            f["Destination Port"] = float(f["port"])

        # 9. Statistical & Flag Completion
        if "FIN Flag Count" not in f:
            f["FIN Flag Count"] = 0.0
        if "RST Flag Count" not in f:
            f["RST Flag Count"] = 0.0
        if "PSH Flag Count" not in f:
            f["PSH Flag Count"] = 1.0 if fwd > 0 and avg_pkt > 300 else 0.0
        if "URG Flag Count" not in f:
            f["URG Flag Count"] = 0.0
        if "CWE Flag Count" not in f:
            f["CWE Flag Count"] = 0.0
        if "ECE Flag Count" not in f:
            f["ECE Flag Count"] = 0.0
        if "Down/Up Ratio" not in f:
            f["Down/Up Ratio"] = round(bwd / max(fwd, 1.0), 5)
        if "Packet Length Min" not in f:
            f["Packet Length Min"] = min(avg_pkt, 60.0) if avg_pkt > 0 else 0.0
        if "Packet Length Max" not in f:
            f["Packet Length Max"] = fwd_max
        if "Packet Length Std" not in f:
            f["Packet Length Std"] = 0.0
        if "Packet Length Variance" not in f:
            f["Packet Length Variance"] = 0.0
        if "Active Mean" not in f:
            f["Active Mean"] = 0.0 if (fwd < 50 and bwd < 50 and dur < 5_000_000) else dur / 2.0
        if "Idle Mean" not in f:
            f["Idle Mean"] = 0.0 if (fwd < 50 and bwd < 50 and dur < 5_000_000) else dur / 2.0

        return f

    FEATURE_ALIASES = {
        "Total Length of Fwd Packets": "Fwd Packets Length Total",
        "Total Length of Bwd Packets": "Bwd Packets Length Total",
        "Average Packet Size": "Avg Packet Size",
        "Init_Win_bytes_forward": "Init Fwd Win Bytes",
        "Init_Win_bytes_backward": "Init Bwd Win Bytes",
        "act_data_pkt_fwd": "Fwd Act Data Packets",
        "min_seg_size_forward": "Fwd Seg Size Min",
        "Fwd Header Length.1": "Fwd Header Length",
    }

    def _normalize_feature_dict(self, flow: dict) -> dict:
        """Ensure all canonical feature column names and common dataset aliases are populated."""
        f = dict(flow)
        for alias, canonical in self.FEATURE_ALIASES.items():
            if canonical not in f and alias in f:
                f[canonical] = f[alias]
            elif alias not in f and canonical in f:
                f[alias] = f[canonical]
        return f

    def _preprocess(self, features: dict | list | np.ndarray) -> np.ndarray:
        if isinstance(features, dict):
            features = self._normalize_feature_dict(features)
            if len(features) < 40:
                features = self._complete_partial_features(features)
                features = self._normalize_feature_dict(features)
            arr = np.array(
                [features.get(col, 0.0) for col in self.feature_cols],
                dtype=np.float32,
            )
        elif isinstance(features, list):
            arr = np.array(features, dtype=np.float32)
        else:
            arr = features.astype(np.float32)

        arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)

        if self.scaler is not None:
            arr = self.scaler.transform(arr.reshape(1, -1))[0]

        return arr

    def _severity(self, attack_type: str, confidence: float) -> dict:
        base = ATTACK_SEVERITY.get(attack_type, 3)
        if attack_type == "ANOMALY":
            score = min(3, base)  # Capped at Medium (score 3) per specification
        else:
            boosted = min(5, base + 1) if confidence > settings.high_severity_threshold else base
            score = boosted if attack_type != "BENIGN" else 0
        return {
            "severity_score": score,
            "severity_label": SEVERITY_LABELS[score],
            "is_attack":      attack_type != "BENIGN",
        }

    @staticmethod
    def _infer_attack_from_flow(flow: dict) -> str:
        """
        Deterministic signature heuristic fallback to guarantee a concrete granular attack class
        instead of ambiguous 'ATTACK' or 'ANOMALY' label.
        """
        f = flow or {}
        port = int(f.get("Destination Port", f.get("port", 80)))
        proto = int(f.get("Protocol", 6))
        fwd = float(f.get("Total Fwd Packets", f.get("Tot Fwd Pkts", 1)))
        bwd = float(f.get("Total Backward Packets", f.get("Tot Bwd Pkts", 0)))
        dur = float(f.get("Flow Duration", 1000))
        syn = float(f.get("SYN Flag Count", 0))
        ack = float(f.get("ACK Flag Count", 0))
        psh = float(f.get("PSH Flag Count", 0))
        fin = float(f.get("FIN Flag Count", 0))
        size = float(f.get("Fwd Packet Length Max", f.get("Fwd Pkt Len Max", 0)))

        # 1. DDoS Floods (Check massive volumetric attacks first)
        if syn > 1000 and ack == 0:
            return "SYN_FLOOD"
        if proto == 17 and fwd > 2000:
            return "UDP_FLOOD" if port != 53 else "DNS_AMPLIFICATION"
        if proto == 1 and fwd > 1000:
            return "ICMP_FLOOD"

        # 2. Scans & Recon
        if (fwd <= 500 and bwd <= 5 and size == 0 and (syn > 0 or fin > 0 or ack == 0)) or (syn > 0 and ack == 0 and fwd <= 1000 and size == 0):
            if fin > 0:
                return "FIN_SCAN"
            if syn > 0 and ack == 0:
                return "PORT_SCAN" if fwd <= 5 else "SYN_SCAN"
            if syn == 0 and ack == 0 and fin == 0:
                return "NULL_SCAN"
            return "PORT_SCAN"

        # 3. Brute Force
        if port == 22 or (dur > 5_000_000 and 200 <= fwd <= 3000 and 100 <= size <= 500):
            return "BRUTE_FORCE_SSH"
        if port == 21:
            return "BRUTE_FORCE_FTP"

        # 4. DoS Fragmentation / Specific Attacks
        # TEARDROP: UDP one-way flood, small packets, mid-range packet count
        if proto == 17 and bwd == 0 and size <= 100 and 10 <= fwd <= 2000:
            return "TEARDROP"
        # PING_OF_DEATH: ICMP one-way with oversized packets
        if proto == 1 and bwd == 0 and size > 1400:
            return "PING_OF_DEATH"
        # LAND_ATTACK: TCP SYN with no ACK, one-way, low packet count to single target
        if proto == 6 and bwd == 0 and syn > 0 and ack == 0 and 1 <= fwd <= 100:
            return "LAND_ATTACK"

        # 5. DoS Layer 7 Attacks
        if port == 80 and fwd > 3000 and size >= 1400:
            return "HTTP_FLOOD"
        if dur > 20_000_000 and size <= 20 and port == 80:
            return "SLOWLORIS"

        # 6. Exfiltration & Anomaly Infiltration
        if (bwd > fwd * 3 and bwd >= 50) or (bwd >= 1000):
            return "DATA_EXFILTRATION"

        # 7. Web Exploits
        if port in [80, 443] and (psh > 10 or size > 800):
            return "SQL_INJECTION" if psh > 20 else "WEB_ATTACK"

        # 8. Malware & Command and Control
        if port in [4444, 1337]:
            return "C2_BEACON"
        if port in [3333, 4444] or dur > 60_000_000:
            return "CRYPTOMINING"

        return "ZERO_DAY_EXPLOIT"

    def predict(self, features: dict | list | np.ndarray) -> dict:
        if not self._loaded:
            raise RuntimeError("Engine not loaded — call load() first")

        flow_dict = features if isinstance(features, dict) else dict(zip(self.feature_cols, features))
        arr     = self._preprocess(features)
        results = {}

        if self.rf_model:
            if hasattr(self.rf_model, "predict_single"):
                results["rf"] = self.rf_model.predict_single(arr)
            else:
                probs = self.rf_model.predict_proba(arr.reshape(1, -1))[0]
                pred_idx = int(np.argmax(probs))
                cname = self.class_names[pred_idx] if pred_idx < len(self.class_names) else str(pred_idx)
                conf = float(probs[pred_idx])
                attack_prob = sum(float(probs[i]) for i in range(len(self.class_names)) if self.class_names[i] != "BENIGN" and i < len(probs))
                is_rf_attack = bool(cname != "BENIGN" or attack_prob >= 0.40)
                results["rf"] = {
                    "prediction": pred_idx,
                    "label": "ATTACK" if is_rf_attack else "BENIGN",
                    "attack_type": cname if cname != "BENIGN" else ("ATTACK" if is_rf_attack else "BENIGN"),
                    "confidence": conf if not is_rf_attack else max(conf, attack_prob),
                    "is_attack": is_rf_attack,
                    "all_probabilities": {self.class_names[i]: float(probs[i]) for i in range(len(self.class_names)) if i < len(probs)}
                }

        if self.xgb_model:
            if hasattr(self.xgb_model, "predict_single"):
                results["xgb"] = self.xgb_model.predict_single(arr)
            else:
                probs = self.xgb_model.predict_proba(arr.reshape(1, -1))[0]
                pred_idx = int(np.argmax(probs))
                cname = self.class_names[pred_idx] if pred_idx < len(self.class_names) else str(pred_idx)
                conf = float(probs[pred_idx])
                results["xgb"] = {
                    "prediction": pred_idx,
                    "label": cname,
                    "confidence": conf,
                    "is_attack": cname != "BENIGN",
                    "all_probabilities": {self.class_names[i]: float(probs[i]) for i in range(len(self.class_names)) if i < len(probs)}
                }

        if self.lstm_model:
            results["lstm"] = self.lstm_model.predict_single(arr)

        if self.iso_model:
            results["iso"] = self.iso_model.predict_single(arr)

        # Anomaly scoring via dual ensemble (Autoencoder + Isolation Forest)
        anomaly_score = None
        is_anomaly = False
        if self.anomaly_ensemble and self.anomaly_preprocessor:
            try:
                flow_dict = features if isinstance(features, dict) else dict(zip(self.feature_cols, features))
                if len(flow_dict) < 40:
                    flow_dict = self._complete_partial_features(flow_dict)
                X_anom = self.anomaly_preprocessor.transform(flow_dict, strict=False)
                score_arr, p_ae, p_if = self.anomaly_ensemble.predict_score(X_anom)
                anomaly_score = float(score_arr[0])
                thresh = 0.82
                is_anomaly = bool(anomaly_score >= thresh)
                results["anomaly_ensemble"] = {
                    "label": "ANOMALY" if is_anomaly else "NORMAL",
                    "anomaly_score": round(anomaly_score, 4),
                    "confidence": round(anomaly_score, 4),
                    "is_attack": is_anomaly,
                    "threshold": round(thresh, 4),
                    "autoencoder_percentile": round(float(p_ae[0]), 4),
                    "isolation_forest_percentile": round(float(p_if[0]), 4),
                }
                # Also synchronize ISO in the model breakdown with the calibrated Isolation Forest
                iso_p = float(p_if[0])
                iso_is_anomaly = iso_p >= thresh
                results["iso"] = {
                    "prediction": 1 if iso_is_anomaly else 0,
                    "label": "ATTACK" if iso_is_anomaly else "BENIGN",
                    "is_attack": iso_is_anomaly,
                    "anomaly_score": round(iso_p, 4),
                    "confidence": round(iso_p if iso_is_anomaly else (1.0 - iso_p), 4),
                    "model": "IsolationForest",
                }
            except Exception as e:
                logger.warning(f"Anomaly scoring failed: {e}")

        # Ensemble voting & resolution across all models
        attack_votes = sum(
            1 for r in results.values()
            if r.get("is_attack", r.get("label") in ["ATTACK", "ANOMALY"])
        )
        total_votes = len(results)

        xgb_res = results.get("xgb", {})
        rf_res = results.get("rf", {})
        iso_res = results.get("iso", {})
        lstm_res = results.get("lstm", {})

        xgb_attack = xgb_res.get("is_attack", False) and xgb_res.get("label") != "BENIGN"
        rf_attack = rf_res.get("is_attack", False)
        lstm_attack = lstm_res.get("is_attack", False)
        supervised_attacks = sum([xgb_attack, rf_attack, lstm_attack])

        # In Enterprise IDS:
        # 1. Supervised attack confirmed when XGBoost or RF detects an attack, or 2+ supervised models agree.
        # 2. Majority of all ensemble models agree (>= 3 / 5).
        # 3. Statistical zero-day anomaly confirmed when dual anomaly detectors (Autoencoder + Isolation Forest)
        #    both detect extreme divergence, or when 1 anomaly detector + 1 supervised model agree.
        has_supervised_attack = (
            (xgb_attack and xgb_res.get("confidence", 0) >= 0.40) or
            (rf_attack and rf_res.get("confidence", 0) >= 0.60) or
            (supervised_attacks >= 2)
        )
        is_majority_attack = (attack_votes >= 3)
        thresh = 0.82
        is_statistical_anomaly = bool(
            (is_anomaly and iso_res.get("is_attack", False) and anomaly_score is not None and anomaly_score >= thresh) or
            ((is_anomaly or iso_res.get("is_attack", False)) and supervised_attacks >= 1)
        )

        ensemble_attack = has_supervised_attack or is_majority_attack or is_statistical_anomaly

        if ensemble_attack:
            candidate_label = xgb_res.get("label")
            if xgb_attack and candidate_label not in ["BENIGN", "ATTACK", "ANOMALY", None, ""]:
                attack_type = candidate_label
                confidence = xgb_res.get("confidence", 0.0)
            else:
                # When XGBoost argmax is BENIGN or generic, check non-benign probabilities
                all_probs = xgb_res.get("all_probabilities", {})
                non_benign = {k: v for k, v in all_probs.items() if k not in ["BENIGN", "ATTACK", "ANOMALY"]}
                if non_benign:
                    top_cand, top_p = max(non_benign.items(), key=lambda x: x[1])
                    if top_p >= 0.20:
                        attack_type = top_cand
                        confidence = max(top_p, rf_res.get("confidence", 0.85))
                    else:
                        attack_type = self._infer_attack_from_flow(flow_dict)
                        confidence = rf_res.get("confidence", 0.88)
                else:
                    attack_type = self._infer_attack_from_flow(flow_dict)
                    confidence = rf_res.get("confidence", 0.88)

            # Safety fallback: guarantee no ambiguous generic label leaks on supervised attacks
            if attack_type in ["ATTACK", "ANOMALY", None, ""]:
                attack_type = self._infer_attack_from_flow(flow_dict)
        else:
            attack_type = "BENIGN"
            benign_confs = [
                xgb_res.get("confidence", 0.0) if not xgb_attack else 0.0,
                rf_res.get("confidence", 0.0) if not rf_attack else 0.0,
                lstm_res.get("confidence", 0.0) if not lstm_attack else 0.0
            ]
            confidence = max(benign_confs) if any(benign_confs) else 0.95

        should_alert = ensemble_attack and confidence >= 0.50

        # Determine SOC action: DROP, REVIEW, or ALLOW
        if ensemble_attack and confidence >= 0.70 and attack_type != "ANOMALY":
            action = "DROP"
        elif ensemble_attack or (is_anomaly and is_statistical_anomaly):
            action = "REVIEW"
        else:
            action = "ALLOW"

        severity = self._severity(attack_type, confidence)
        attack_category = ATTACK_CATEGORY_MAP.get(attack_type, "Threat Detected" if ensemble_attack else "Normal Traffic")

        return {
            "is_attack":        ensemble_attack,
            "attack_type":      attack_type,
            "attack_category":  attack_category,
            "confidence":       round(confidence, 4),
            "action":           action,
            "should_alert":     should_alert,
            "anomaly_score":    round(anomaly_score, 4) if anomaly_score is not None else None,
            "is_anomaly":       is_anomaly,
            "model_results":    results,
            "ensemble_votes":   {"attack": attack_votes, "total": total_votes},
            **severity,
        }

    @property
    def is_ready(self) -> bool:
        # Full production readiness requires certified real supervised models
        is_demo_mode = os.environ.get("KOPO_DEMO_MODE", "false").lower() in ["true", "1", "yes"]
        if self.data_origin == "synthetic" and not is_demo_mode:
            return False
        return self._loaded and any([
            self.rf_model, self.xgb_model, self.lstm_model, self.iso_model, self.anomaly_ensemble
        ])

    def status(self) -> dict:
        manifest = getattr(self, "active_manifest", {}) or {}
        return {
            "loaded": self._loaded,
            "active_run_id": self.active_run_id,
            "data_origin": self.data_origin,
            "certified": bool(manifest.get("certified", False)),
            "run_type": manifest.get("run_type", "unknown"),
            "training_dataset": manifest.get("training_dataset"),
            "decision_threshold": manifest.get("decision_threshold", 0.5),
            "excluded_models": manifest.get("excluded_models", []),
            "anomaly_origin": getattr(self, "anomaly_origin", "real"),
            "anomaly_ready": getattr(self, "anomaly_ready", False),
            "models": {
                "random_forest":    self.rf_model   is not None,
                "xgboost":          self.xgb_model  is not None,
                "lstm":             self.lstm_model is not None,
                "isolation_forest": self.iso_model  is not None,
                "anomaly_ensemble": self.anomaly_ensemble is not None,
            },
            "n_features":  len(self.feature_cols),
            "class_names": self.class_names,
        }
