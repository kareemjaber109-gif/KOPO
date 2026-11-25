import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import math

engine = DetectionEngine()
engine.load()

def generate_attack_params(label):
    dur, fwd, bwd, size, syn, ack, fin, rst, psh, urg, proto, port = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 80
    fwd_win, bwd_win = 8192, 0

    if label in ['BENIGN', 'Normal HTTP', 'Normal']:
        dur = 350000; fwd = 10; bwd = 8; size = 220; syn = 0; ack = 0; psh = 1; port = 443; proto = 6
        fwd_win = 8192; bwd_win = 172
    elif any(k in label for k in ['PORT_SCAN', 'SYN_SCAN', 'NULL_SCAN', 'FIN_SCAN', 'XMAS_SCAN', 'Port Scan']):
        dur = 341670; fwd = 3; bwd = 6; size = 18; syn = 0 if 'NULL_SCAN' in label else 1
        fin = 1 if ('FIN_SCAN' in label or 'XMAS_SCAN' in label) else 0
        psh = 0 if ('FIN_SCAN' in label or 'NULL_SCAN' in label) else 1
        urg = 1 if 'XMAS_SCAN' in label else 0
        ack = 0; port = 445; proto = 6
        fwd_win = 29200; bwd_win = 227
    elif any(k in label for k in ['SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD', 'AMPLIFICATION', 'SMURF', 'DDOS', 'DDoS']):
        dur = 8927790; fwd = 5; bwd = 0; size = 6; syn = 1 if 'SYN' in label else 0; ack = 1; psh = 0
        proto = 17 if ('UDP' in label or 'AMPLIFICATION' in label) else (1 if ('ICMP' in label or 'SMURF' in label) else 6)
        port = 53 if 'DNS' in label else (123 if 'NTP' in label else 80)
        fwd_win = 256; bwd_win = -1
    elif any(k in label for k in ['HTTP_FLOOD', 'SLOW', 'DOS', 'DoS', 'TEARDROP', 'PING_OF_DEATH', 'LAND_ATTACK']):
        dur = 35000000 if 'SLOW' in label else 13994
        fwd = 3; bwd = 1
        size = 1473 if label == 'PING_OF_DEATH' else (48 if label == 'TEARDROP' else 6)
        syn = 1 if label == 'LAND_ATTACK' else 0; ack = 0; psh = 0
        proto = 17 if label == 'TEARDROP' else (1 if label == 'PING_OF_DEATH' else 6)
        port = 0 if label in ['TEARDROP', 'PING_OF_DEATH'] else 80
        fwd_win = 0; bwd_win = 235
    elif any(k in label for k in ['BRUTE_FORCE', 'PATATOR', 'SPRAYING', 'STUFFING', 'Brute Force']):
        dur = 12043459; fwd = 21; bwd = 32; size = 640; syn = 0; ack = 0; psh = 1
        port = 21 if 'FTP' in label else (80 if 'WEB' in label else 22); proto = 6
        fwd_win = 29200; bwd_win = 247
    elif any(k in label for k in ['SQL', 'XSS', 'WEB_ATTACK', 'HEARTBLEED', 'PHISHING', 'INJECTION', 'TRAVERSAL']):
        dur = 5659068; fwd = 3; bwd = 1; size = 18; syn = 0; ack = 0; psh = 1
        port = 443 if 'HEARTBLEED' in label else 80; proto = 6
        fwd_win = 29200; bwd_win = 28960
    elif any(k in label for k in ['BOT', 'RANSOM', 'C2', 'MINING', 'Malware']):
        dur = 1013034; fwd = 3; bwd = 3; size = 6; syn = 0; ack = 0; psh = 1
        port = 4444 if 'C2' in label else (3333 if 'MINING' in label else (445 if 'RANSOM' in label else 6667))
        proto = 6; fwd_win = 8192; bwd_win = 0
    elif any(k in label for k in ['ZERO_DAY', 'EXFILTRATION', 'SPAM', 'Zero-Day']):
        dur = 501734; fwd = 1; bwd = 1; size = 1460; syn = 0; ack = 1; urg = 4; port = 8088; proto = 6
        fwd_win = 1024; bwd_win = 1024
    else:
        dur = 500000; fwd = 5; bwd = 2; size = 500; syn = 1; ack = 2; port = 80; proto = 6
        fwd_win = 8192; bwd_win = 0

    return {
        'dur': dur, 'fwd': fwd, 'bwd': bwd, 'size': size, 'syn': syn, 'ack': ack,
        'fin': fin, 'rst': rst, 'psh': psh, 'urg': urg, 'proto': proto, 'port': port,
        'fwd_win': fwd_win, 'bwd_win': bwd_win
    }

def make_dynamic_flow(label):
    p = generate_attack_params(label)
    total_fwd = p['fwd'] * p['size']
    total_bwd = p['bwd'] * p['size']
    dur_sec = max(p['dur'] / 1e6, 1e-6)
    iat = p['dur'] / max(p['fwd'], 1)
    bwd_iat = p['dur'] / p['bwd'] if p['bwd'] else 0

    return {
        "Destination Port": p['port'],
        "Protocol": p['proto'],
        "Flow Duration": p['dur'],
        "Total Fwd Packets": p['fwd'],
        "Total Backward Packets": p['bwd'],
        "Total Length of Fwd Packets": total_fwd,
        "Total Length of Bwd Packets": total_bwd,
        "Fwd Packet Length Max": p['size'],
        "Fwd Packet Length Min": max(0, int(p['size'] * 0.2)),
        "Fwd Packet Length Mean": round(p['size'] * (0.85 if p['size'] > 0 else 0), 1),
        "Fwd Packet Length Std": round(p['size'] * 0.25, 1),
        "Bwd Packet Length Max": p['size'] if p['bwd'] else 0,
        "Bwd Packet Length Min": max(0, int(p['size'] * 0.2)) if p['bwd'] else 0,
        "Bwd Packet Length Mean": round(p['size'] * 0.85, 1) if p['bwd'] else 0.0,
        "Bwd Packet Length Std": round(p['size'] * 0.25, 1) if p['bwd'] else 0.0,
        "Flow Bytes/s": round(((total_fwd + total_bwd) / dur_sec), 2),
        "Flow Packets/s": round(((p['fwd'] + p['bwd']) / dur_sec), 2),
        "Flow IAT Mean": round(iat, 2),
        "Flow IAT Std": round(iat * 0.45, 2),
        "Flow IAT Max": round(iat * 2.2, 2),
        "Flow IAT Min": max(1, int(iat * 0.05)),
        "Fwd IAT Total": p['dur'],
        "Fwd IAT Mean": round(iat, 2),
        "Fwd IAT Std": round(iat * 0.45, 2),
        "Fwd IAT Max": round(iat * 2.2, 2),
        "Fwd IAT Min": max(1, int(iat * 0.05)),
        "Bwd IAT Total": p['dur'] if p['bwd'] else 0,
        "Bwd IAT Mean": round(bwd_iat, 2),
        "Bwd IAT Std": round(bwd_iat * 0.45, 2),
        "Bwd IAT Max": round(bwd_iat * 2.2, 2),
        "Bwd IAT Min": max(1, int(bwd_iat * 0.05)) if p['bwd'] else 0,
        "Fwd PSH Flags": 1 if p['psh'] > 0 or p['size'] > 300 else 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 1 if p['urg'] > 0 else 0,
        "Bwd URG Flags": 0,
        "Fwd Header Length": p['fwd'] * 20,
        "Bwd Header Length": p['bwd'] * 20,
        "Fwd Packets/s": round((p['fwd'] / dur_sec), 2),
        "Bwd Packets/s": round((p['bwd'] / dur_sec), 2),
        "Min Packet Length": max(0, int(p['size'] * 0.2)),
        "Max Packet Length": max(p['size'], 60),
        "Packet Length Mean": round(p['size'] * (0.85 if p['size'] > 0 else 0), 1),
        "Packet Length Std": round(p['size'] * 0.28, 1),
        "Packet Length Variance": round(p['size'] * p['size'] * 0.08, 1),
        "FIN Flag Count": p['fin'],
        "SYN Flag Count": p['syn'],
        "RST Flag Count": p['rst'],
        "PSH Flag Count": p['psh'],
        "ACK Flag Count": p['ack'],
        "URG Flag Count": p['urg'],
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": round((p['bwd'] / max(p['fwd'], 1)), 2),
        "Average Packet Size": float(p['size']),
        "Avg Fwd Segment Size": float(p['size']),
        "Avg Bwd Segment Size": float(p['size']) if p['bwd'] else 0.0,
        "Fwd Header Length.1": p['fwd'] * 20,
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": p['fwd'],
        "Subflow Fwd Bytes": total_fwd,
        "Subflow Bwd Packets": p['bwd'],
        "Subflow Bwd Bytes": total_bwd,
        "Init_Win_bytes_forward": p['fwd_win'],
        "Init_Win_bytes_backward": p['bwd_win'],
        "act_data_pkt_fwd": max(1, int(p['fwd'] * 0.7)),
        "min_seg_size_forward": 20,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0,
        "Idle Min": 0
    }

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

print(f"{'Subtype':20s} | {'Verdict':18s} | {'Category':16s} | {'XGB':14s} | {'RF':14s} | {'LSTM':8s} | {'Action':6s}")
print("-" * 110)

for s in subtypes:
    flow = make_dynamic_flow(s)
    res = engine.predict(flow)
    xgb = f"{res['model_results']['xgb']['label']} ({res['model_results']['xgb']['confidence']*100:.0f}%)"
    rf = f"{res['model_results']['rf']['label']} ({res['model_results']['rf']['confidence']*100:.0f}%)"
    lstm = res['model_results']['lstm']['label']
    print(f"{s:20s} | {res['attack_type']:18s} | {res['attack_category']:16s} | {xgb:14s} | {rf:14s} | {lstm:8s} | {res['action']:6s}")
