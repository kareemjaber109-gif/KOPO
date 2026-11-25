import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import json
import random

engine = DetectionEngine()
engine.load()

vflows = json.load(open('data/models/verified_attack_flows.json'))

# Clean realistic templates mapped from verified flows
MAPPING = {
    'PORT_SCAN': 'PortScan',
    'SYN_SCAN': 'PortScan',
    'FIN_SCAN': 'PortScan',
    'NULL_SCAN': 'PortScan',
    'XMAS_SCAN': 'PortScan',
    'HTTP_FLOOD': 'DoS',
    'SLOWLORIS': 'DoS',
    'SLOWHTTPTEST': 'DoS',
    'PING_OF_DEATH': 'DoS',
    'TEARDROP': 'DoS',
    'LAND_ATTACK': 'DoS',
    'SYN_FLOOD': 'DDoS',
    'UDP_FLOOD': 'DDoS',
    'ICMP_FLOOD': 'DDoS',
    'DNS_AMPLIFICATION': 'DDoS',
    'NTP_AMPLIFICATION': 'DDoS',
    'SMURF': 'DDoS',
    'BRUTE_FORCE_SSH': 'BruteForce',
    'BRUTE_FORCE_FTP': 'BruteForce',
    'BRUTE_FORCE_WEB': 'BruteForce',
    'SSH_PATATOR': 'BruteForce',
    'FTP_PATATOR': 'BruteForce',
    'SQL_INJECTION': 'WebAttack',
    'XSS': 'WebAttack',
    'WEB_ATTACK': 'WebAttack',
    'HEARTBLEED': 'WebAttack',
    'PHISHING': 'WebAttack',
    'BOTNET': 'Bot',
    'RANSOMWARE': 'Bot',
    'C2_BEACON': 'Bot',
    'CRYPTOMINING': 'Bot',
    'ZERO_DAY_EXPLOIT': 'ZERO_DAY',
    'DATA_EXFILTRATION': 'ZERO_DAY',
    'EMAIL_SPAM': 'ZERO_DAY',
    'BENIGN': 'BENIGN'
}

print(f"{'Subtype':20s} | {'Verdict':18s} | {'Category':16s} | {'XGB':12s} | {'RF':12s} | {'LSTM':8s} | {'Action':6s}")
print("-" * 105)

for subtype, tmpl_key in MAPPING.items():
    if tmpl_key == 'ZERO_DAY':
        flow = dict(vflows['BENIGN'])
        flow['Destination Port'] = 8088
        flow['Protocol'] = 6
        flow['Flow Duration'] = 501734
        flow['Total Fwd Packets'] = 1
        flow['Total Backward Packets'] = 1
        flow['URG Flag Count'] = 4
        flow['ACK Flag Count'] = 1
        flow['Fwd Packet Length Max'] = 1460
        flow['Init Fwd Win Bytes'] = 1024
        flow['Init Bwd Win Bytes'] = 1024
    else:
        flow = dict(vflows[tmpl_key])
        # Add slight realistic subtype port variation
        if subtype == 'BRUTE_FORCE_FTP' or subtype == 'FTP_PATATOR':
            flow['Destination Port'] = 21
        elif subtype == 'BRUTE_FORCE_SSH' or subtype == 'SSH_PATATOR':
            flow['Destination Port'] = 22
        elif subtype == 'HEARTBLEED':
            flow['Destination Port'] = 443
        elif subtype == 'C2_BEACON':
            flow['Destination Port'] = 4444
        elif subtype == 'CRYPTOMINING':
            flow['Destination Port'] = 3333
        elif subtype == 'UDP_FLOOD' or subtype == 'DNS_AMPLIFICATION':
            flow['Destination Port'] = 53
            flow['Protocol'] = 17
        elif subtype == 'NTP_AMPLIFICATION':
            flow['Destination Port'] = 123
            flow['Protocol'] = 17
        elif subtype == 'ICMP_FLOOD' or subtype == 'SMURF':
            flow['Protocol'] = 1
            flow['Destination Port'] = 0

    res = engine.predict(flow)
    xgb = res['model_results']['xgb']['label'] + f" ({res['model_results']['xgb']['confidence']*100:.0f}%)"
    rf = res['model_results']['rf']['label'] + f" ({res['model_results']['rf']['confidence']*100:.0f}%)"
    lstm = res['model_results']['lstm']['label']
    print(f"{subtype:20s} | {res['attack_type']:18s} | {res['attack_category']:16s} | {xgb:12s} | {rf:12s} | {lstm:8s} | {res['action']:6s}")
