import requests
import json

test_flows = {
    'DoS (77F User Payload)': {
        'Destination Port': 80, 'Flow Duration': 500000, 'Total Fwd Packets': 8000, 'Total Backward Packets': 50,
        'Total Length of Fwd Packets': 11680000, 'Total Length of Bwd Packets': 73000, 'Fwd Packet Length Max': 1460,
        'Flow Bytes/s': 23360000.0, 'Flow Packets/s': 16100.0, 'SYN Flag Count': 1, 'ACK Flag Count': 50, 'Avg Packet Size': 1460.0,
        'Active Mean': 250000.0, 'Active Std': 0.0, 'Active Max': 250000, 'Active Min': 250000, 'Idle Mean': 250000.0, 'Idle Std': 0.0, 'Idle Max': 250000, 'Idle Min': 250000
    },
    'DoS (10F)': {
        'Protocol': 6, 'Flow Duration': 500000, 'Total Fwd Packets': 8000, 'Total Backward Packets': 50,
        'Fwd Packet Length Max': 1460, 'Flow Bytes/s': 23360000, 'Flow Packets/s': 16100, 'SYN Flag Count': 1, 'ACK Flag Count': 50, 'Avg Packet Size': 1460
    },
    'Brute Force (10F)': {
        'Protocol': 6, 'Flow Duration': 25000000, 'Total Fwd Packets': 1200, 'Total Backward Packets': 1100,
        'Fwd Packet Length Max': 350, 'Flow Bytes/s': 16800.0, 'Flow Packets/s': 92.0, 'SYN Flag Count': 1, 'ACK Flag Count': 2300, 'Avg Packet Size': 300.0
    },
    'Brute Force (77F)': {
        'Destination Port': 22, 'Protocol': 6, 'Flow Duration': 30000000, 'Total Fwd Packets': 1000, 'Total Backward Packets': 1000,
        'Total Length of Fwd Packets': 300000, 'Total Length of Bwd Packets': 300000, 'Fwd Packet Length Max': 300,
        'Flow Bytes/s': 20000.0, 'Flow Packets/s': 66.7, 'SYN Flag Count': 1, 'ACK Flag Count': 2000, 'Avg Packet Size': 300.0
    },
    'DDoS SYN Flood (10F)': {
        'Protocol': 6, 'Flow Duration': 100000, 'Total Fwd Packets': 5000, 'Total Backward Packets': 0,
        'Fwd Packet Length Max': 60, 'Flow Bytes/s': 3000000.0, 'Flow Packets/s': 50000.0, 'SYN Flag Count': 5000, 'ACK Flag Count': 0, 'Avg Packet Size': 60.0
    },
    'Port Scan (10F)': {
        'Protocol': 6, 'Flow Duration': 1200, 'Total Fwd Packets': 2, 'Total Backward Packets': 0,
        'Fwd Packet Length Max': 0, 'Flow Bytes/s': 0.0, 'Flow Packets/s': 1666.67, 'SYN Flag Count': 2, 'ACK Flag Count': 0, 'Avg Packet Size': 0.0
    },
    'Web Attack (10F)': {
        'Protocol': 6, 'Flow Duration': 4500000, 'Total Fwd Packets': 40, 'Total Backward Packets': 40,
        'Fwd Packet Length Max': 1200, 'Flow Bytes/s': 15000.0, 'Flow Packets/s': 17.8, 'SYN Flag Count': 1, 'ACK Flag Count': 40, 'Avg Packet Size': 900.0
    },
    'Normal HTTP (10F)': {
        'Protocol': 6, 'Flow Duration': 2100000, 'Total Fwd Packets': 8, 'Total Backward Packets': 6,
        'Fwd Packet Length Max': 220, 'Flow Bytes/s': 1250.0, 'Flow Packets/s': 6.67, 'SYN Flag Count': 1, 'ACK Flag Count': 6, 'Avg Packet Size': 180.0
    },
    'Normal HTTP (77F)': {
        'Destination Port': 443, 'Protocol': 6, 'Flow Duration': 1800000, 'Total Fwd Packets': 12, 'Total Backward Packets': 10,
        'Total Length of Fwd Packets': 1200, 'Total Length of Bwd Packets': 8000, 'Fwd Packet Length Max': 512,
        'Flow Bytes/s': 5111.0, 'Flow Packets/s': 12.2, 'SYN Flag Count': 1, 'ACK Flag Count': 10, 'Avg Packet Size': 418.0,
        'Active Mean': 0.0, 'Active Std': 0.0, 'Active Max': 0, 'Active Min': 0, 'Idle Mean': 0.0, 'Idle Std': 0.0, 'Idle Max': 0, 'Idle Min': 0
    }
}

print(f"{'Test Flow':24} | {'Predicted':12} | {'Attack?':7} | {'Conf':7} | {'XGBoost':18} | {'RF':14} | {'LSTM':14} | Votes")
print("-" * 115)

for name, payload in test_flows.items():
    r = requests.post('http://127.0.0.1:8000/api/detect', json=payload).json()
    xgb_lbl = r['model_results'].get('xgb', {}).get('label', '—')
    xgb_conf = r['model_results'].get('xgb', {}).get('confidence', 0)
    rf_lbl = r['model_results'].get('rf', {}).get('label', '—')
    rf_conf = r['model_results'].get('rf', {}).get('confidence', 0)
    lstm_lbl = r['model_results'].get('lstm', {}).get('label', '—')
    lstm_conf = r['model_results'].get('lstm', {}).get('confidence', 0)
    final_type = r.get('attack_type', '—')
    is_atk = r.get('is_attack', False)
    conf = r.get('confidence', 0)
    votes = r.get('ensemble_votes', {})
    
    xgb_str = f"{xgb_lbl} ({xgb_conf*100:.1f}%)"
    rf_str = f"{rf_lbl} ({rf_conf*100:.1f}%)"
    lstm_str = f"{lstm_lbl} ({lstm_conf*100:.1f}%)"
    vote_str = f"{votes.get('attack', 0)}/{votes.get('total', 0)}"
    
    print(f"{name:24} | {final_type:12} | {str(is_atk):7} | {conf*100:5.1f}% | {xgb_str:18} | {rf_str:14} | {lstm_str:14} | {vote_str}")
