import sys
sys.path.insert(0, ".")
import json
import random
from src.ml.detection_engine import DetectionEngine

engine = DetectionEngine()
engine.load()

vflows = json.load(open('data/models/verified_attack_flows.json'))

# Verify templates available
print("Loaded templates:", list(vflows.keys()))

SUBTYPE_TO_TEMPLATE = {
    # Recon & Scans
    'PORT_SCAN': ('PortScan', {'Destination Port': 445}),
    'SYN_SCAN': ('PortScan', {'Destination Port': 80, 'SYN Flag Count': 1, 'PSH Flag Count': 0}),
    'NULL_SCAN': ('PortScan', {'Destination Port': 80, 'SYN Flag Count': 0, 'PSH Flag Count': 0, 'FIN Flag Count': 0, 'ACK Flag Count': 0}),
    'FIN_SCAN': ('PortScan', {'Destination Port': 80, 'FIN Flag Count': 1, 'PSH Flag Count': 0}),
    'XMAS_SCAN': ('PortScan', {'Destination Port': 80, 'FIN Flag Count': 1, 'PSH Flag Count': 1, 'URG Flag Count': 1}),

    # DoS Attacks
    'HTTP_FLOOD': ('DoS', {'Destination Port': 80, 'Protocol': 6}),
    'SLOWLORIS': ('DoS', {'Destination Port': 80, 'Protocol': 6, 'Flow Duration': 35000000.0}),
    'SLOWHTTPTEST': ('DoS', {'Destination Port': 80, 'Protocol': 6, 'Flow Duration': 25000000.0}),
    'PING_OF_DEATH': ('DoS', {'Destination Port': 0, 'Protocol': 1, 'Fwd Packet Length Max': 1473.0, 'Packet Length Max': 1473.0}),
    'TEARDROP': ('DoS', {'Destination Port': 0, 'Protocol': 17, 'Fwd Packet Length Max': 48.0, 'Packet Length Max': 48.0}),
    'LAND_ATTACK': ('DoS', {'Destination Port': 80, 'Protocol': 6, 'Total Backward Packets': 0.0, 'Subflow Bwd Packets': 0.0}),

    # DDoS & Floods
    'SYN_FLOOD': ('DDoS', {'Destination Port': 80, 'Protocol': 6, 'SYN Flag Count': 1}),
    'UDP_FLOOD': ('DDoS', {'Destination Port': 53, 'Protocol': 17}),
    'ICMP_FLOOD': ('DDoS', {'Destination Port': 0, 'Protocol': 1}),
    'DNS_AMPLIFICATION': ('DDoS', {'Destination Port': 53, 'Protocol': 17}),
    'NTP_AMPLIFICATION': ('DDoS', {'Destination Port': 123, 'Protocol': 17}),
    'SMURF': ('DDoS', {'Destination Port': 0, 'Protocol': 1}),

    # Brute Force
    'BRUTE_FORCE_SSH': ('BruteForce', {'Destination Port': 22}),
    'BRUTE_FORCE_FTP': ('BruteForce', {'Destination Port': 21}),
    'BRUTE_FORCE_WEB': ('BruteForce', {'Destination Port': 80}),
    'SSH_PATATOR': ('BruteForce', {'Destination Port': 22}),
    'FTP_PATATOR': ('BruteForce', {'Destination Port': 21}),

    # Web Attacks
    'SQL_INJECTION': ('WebAttack', {'Destination Port': 80}),
    'XSS': ('WebAttack', {'Destination Port': 80}),
    'WEB_ATTACK': ('WebAttack', {'Destination Port': 80}),
    'HEARTBLEED': ('WebAttack', {'Destination Port': 443}),
    'PHISHING': ('WebAttack', {'Destination Port': 80}),

    # Malware & C2
    'BOTNET': ('Bot', {'Destination Port': 6667}),
    'RANSOMWARE': ('Bot', {'Destination Port': 445}),
    'C2_BEACON': ('Bot', {'Destination Port': 4444}),
    'CRYPTOMINING': ('Bot', {'Destination Port': 3333}),

    # Zero-Day
    'ZERO_DAY_EXPLOIT': ('ZERO_DAY', {}),
    'DATA_EXFILTRATION': ('ZERO_DAY', {'Destination Port': 443}),
    'EMAIL_SPAM': ('ZERO_DAY', {'Destination Port': 25}),

    # Normal
    'BENIGN': ('BENIGN', {'Destination Port': 443, 'Protocol': 6, 'Init Fwd Win Bytes': 8192, 'Init Bwd Win Bytes': 172, 'PSH Flag Count': 1})
}

print(f"{'Subtype':20s} | {'Verdict':18s} | {'Category':16s} | {'XGB':14s} | {'RF':14s} | {'LSTM':8s} | {'Action':6s}")
print("-" * 110)

all_passed = True
for subtype, (tmpl_name, overrides) in SUBTYPE_TO_TEMPLATE.items():
    if tmpl_name == 'ZERO_DAY':
        flow = {
            "Destination Port": overrides.get('Destination Port', 8088),
            "Protocol": 6,
            "Flow Duration": 501734,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "URG Flag Count": 4,
            "ACK Flag Count": 1,
            "Fwd Packet Length Max": 1460,
            "Init Fwd Win Bytes": 1024,
            "Init Bwd Win Bytes": 1024
        }
    else:
        flow = dict(vflows[tmpl_name])
        flow.update(overrides)

    res = engine.predict(flow)
    xgb_str = f"{res['model_results']['xgb']['label']} ({res['model_results']['xgb']['confidence']*100:.0f}%)"
    rf_str = f"{res['model_results']['rf']['label']} ({res['model_results']['rf']['confidence']*100:.0f}%)"
    lstm_str = res['model_results']['lstm']['label']

    is_ok = True
    if subtype == 'BENIGN':
        if res['attack_type'] != 'BENIGN':
            is_ok = False
    elif subtype in ['ZERO_DAY_EXPLOIT', 'DATA_EXFILTRATION', 'EMAIL_SPAM']:
        if res['attack_type'] not in ['ZERO_DAY_EXPLOIT', 'DATA_EXFILTRATION', 'EMAIL_SPAM', 'ANOMALY']:
            is_ok = False
    else:
        # Supervised attack
        if res['attack_type'] == 'BENIGN':
            is_ok = False

    status = "OK" if is_ok else "FAIL"
    if not is_ok:
        all_passed = False

    print(f"{subtype:20s} | {res['attack_type']:18s} | {res['attack_category']:16s} | {xgb_str:14s} | {rf_str:14s} | {lstm_str:8s} | {res['action']:6s} [{status}]")

print("\nALL PASSED:", all_passed)
