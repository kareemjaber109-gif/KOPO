import sys
sys.path.insert(0, ".")
import json
import random
from src.ml.detection_engine import DetectionEngine

engine = DetectionEngine()
engine.load()

templates = json.load(open('frontend/src/pages/attackTemplates.json'))

def make_dynamic_flow_js(label, mode=77):
    is_benign = label in ['BENIGN', 'Normal HTTP', 'Normal']
    
    if is_benign:
        port = random.choice([80, 443])
        dur = random.randint(110000, 630000)
        fwd = random.randint(7, 13)
        bwd = random.randint(5, 10)
        fwd_max = random.randint(180, 260)
        fwd_mean = round(fwd_max * (0.28 + random.random() * 0.1), 2)
        fwd_std = round(fwd_max * (0.40 + random.random() * 0.08), 2)
        total_fwd = int(fwd * fwd_mean)
        bwd_max = random.randint(1200, 1460)
        bwd_mean = round(bwd_max * (0.32 + random.random() * 0.1), 2)
        bwd_std = round(bwd_max * (0.42 + random.random() * 0.06), 2)
        total_bwd = int(bwd * bwd_mean)
        dur_sec = max(dur / 1e6, 1e-6)
        iat = dur / max(fwd + bwd - 1, 1)
        pkt_mean = round((total_fwd + total_bwd) / (fwd + bwd), 2)
        bwd_win = random.choice([115, 172, 251])

        flow = dict(templates['BENIGN'])
        flow.update({
            "Destination Port": port,
            "Protocol": 6,
            "Flow Duration": dur,
            "Total Fwd Packets": fwd,
            "Total Backward Packets": bwd,
            "Total Length of Fwd Packets": total_fwd,
            "Total Length of Bwd Packets": total_bwd,
            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_std,
            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,
            "Flow Bytes/s": round((total_fwd + total_bwd) / dur_sec, 2),
            "Flow Packets/s": round((fwd + bwd) / dur_sec, 2),
            "Flow IAT Mean": round(iat, 2),
            "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": bwd_win,
            "Init Fwd Win Bytes": 8192,
            "Init Bwd Win Bytes": bwd_win,
            "PSH Flag Count": 1
        })
        return flow

    # Attack Flows
    if any(k in label for k in ['PORT_SCAN', 'SYN_SCAN', 'NULL_SCAN', 'FIN_SCAN', 'XMAS_SCAN', 'Port Scan']):
        flow = dict(templates['PortScan'])
        port = random.randint(1, 1024)
        flow['Destination Port'] = port
        if 'SYN_SCAN' in label:
            flow['SYN Flag Count'] = 1
            flow['PSH Flag Count'] = 0
        elif 'FIN_SCAN' in label:
            flow['FIN Flag Count'] = 1
            flow['PSH Flag Count'] = 0
        elif 'NULL_SCAN' in label:
            flow['SYN Flag Count'] = 0
            flow['ACK Flag Count'] = 0
            flow['FIN Flag Count'] = 0
            flow['PSH Flag Count'] = 0
        elif 'XMAS_SCAN' in label:
            flow['FIN Flag Count'] = 1
            flow['PSH Flag Count'] = 1
            flow['URG Flag Count'] = 1
    elif any(k in label for k in ['SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD', 'AMPLIFICATION', 'SMURF', 'DDOS', 'DDoS']):
        flow = dict(templates['DDoS'])
        if 'UDP_FLOOD' in label or 'DNS_AMPLIFICATION' in label:
            flow['Protocol'] = 17
            flow['Destination Port'] = 53
        elif 'NTP_AMPLIFICATION' in label:
            flow['Protocol'] = 17
            flow['Destination Port'] = 123
        elif 'ICMP_FLOOD' in label or 'SMURF' in label:
            flow['Protocol'] = 1
            flow['Destination Port'] = 0
        elif 'SYN_FLOOD' in label:
            flow['Protocol'] = 6
            flow['Destination Port'] = 80
            flow['SYN Flag Count'] = 1
    elif any(k in label for k in ['HTTP_FLOOD', 'SLOW', 'DOS', 'DoS', 'TEARDROP', 'PING_OF_DEATH', 'LAND_ATTACK']):
        flow = dict(templates['DoS'])
        if 'SLOW' in label:
            flow['Flow Duration'] = random.randint(25000000, 45000000)
        elif 'PING_OF_DEATH' in label:
            flow['Protocol'] = 1
            flow['Destination Port'] = 0
            flow['Fwd Packet Length Max'] = 1473
            flow['Packet Length Max'] = 1473
        elif 'TEARDROP' in label:
            flow['Protocol'] = 17
            flow['Destination Port'] = 0
            flow['Fwd Packet Length Max'] = 48
            flow['Packet Length Max'] = 48
        elif 'LAND_ATTACK' in label:
            flow['Destination Port'] = 80
            flow['Total Backward Packets'] = 0
            flow['Subflow Bwd Packets'] = 0
    elif any(k in label for k in ['BRUTE_FORCE', 'PATATOR', 'SPRAYING', 'STUFFING', 'Brute Force']):
        flow = dict(templates['BruteForce'])
        flow['Destination Port'] = 21 if 'FTP' in label else (80 if 'WEB' in label else 22)
    elif any(k in label for k in ['SQL', 'XSS', 'WEB_ATTACK', 'HEARTBLEED', 'PHISHING', 'INJECTION', 'TRAVERSAL']):
        flow = dict(templates['WebAttack'])
        flow['Destination Port'] = 443 if 'HEARTBLEED' in label else 80
    elif any(k in label for k in ['BOT', 'RANSOM', 'C2', 'MINING', 'Malware']):
        flow = dict(templates['Bot'])
        flow['Destination Port'] = 4444 if 'C2' in label else (3333 if 'MINING' in label else (445 if 'RANSOM' in label else 6667))
    elif any(k in label for k in ['ZERO_DAY', 'EXFILTRATION', 'SPAM', 'Zero-Day']):
        flow = dict(templates['ZeroDay'])
        if 'DATA_EXFILTRATION' in label:
            flow['Destination Port'] = 9001
            flow['Total Backward Packets'] = 1500
            flow['Subflow Bwd Packets'] = 1500
            flow['Total Length of Bwd Packets'] = 2190000
            flow['Bwd Packets Length Total'] = 2190000
        elif 'EMAIL_SPAM' in label:
            flow['Destination Port'] = 25
            flow['URG Flag Count'] = 4
    else:
        flow = dict(templates['PortScan'])

    # Light jitter
    jitter = random.uniform(0.97, 1.03)
    flow['Flow Duration'] = round(flow['Flow Duration'] * jitter)

    return flow

subtypes = [
    'BENIGN',
    'HTTP_FLOOD', 'SLOWLORIS', 'SLOWHTTPTEST', 'PING_OF_DEATH', 'TEARDROP', 'LAND_ATTACK',
    'SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD', 'DNS_AMPLIFICATION', 'NTP_AMPLIFICATION', 'SMURF',
    'PORT_SCAN', 'SYN_SCAN', 'NULL_SCAN', 'FIN_SCAN', 'XMAS_SCAN',
    'BRUTE_FORCE_SSH', 'BRUTE_FORCE_FTP', 'BRUTE_FORCE_WEB', 'SSH_PATATOR', 'FTP_PATATOR',
    'SQL_INJECTION', 'XSS', 'WEB_ATTACK', 'HEARTBLEED', 'PHISHING',
    'BOTNET', 'RANSOMWARE', 'C2_BEACON', 'CRYPTOMINING',
    'ZERO_DAY_EXPLOIT', 'DATA_EXFILTRATION', 'EMAIL_SPAM'
]

print(f"{'Subtype':20s} | {'Verdict':18s} | {'Category':16s} | {'XGB':14s} | {'RF':14s} | {'Action':6s}")
print("-" * 100)

for s in subtypes:
    flow = make_dynamic_flow_js(s)
    res = engine.predict(flow)
    xgb_s = f"{res['model_results']['xgb']['label']} ({res['model_results']['xgb']['confidence']*100:.0f}%)"
    rf_s = f"{res['model_results']['rf']['label']} ({res['model_results']['rf']['confidence']*100:.0f}%)"
    print(f"{s:20s} | {res['attack_type']:18s} | {res['attack_category']:16s} | {xgb_s:14s} | {rf_s:14s} | {res['action']:6s}")
