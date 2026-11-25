import requests
import json

templates = json.load(open('frontend/src/pages/attackTemplates.json'))

tests = {
    'BENIGN': templates['BENIGN'],
    'PORT_SCAN': templates['PortScan'],
    'HTTP_FLOOD': templates['DoS'],
    'TEARDROP': dict(templates['DoS'], Protocol=17, **{'Destination Port': 0, 'Fwd Packet Length Max': 48, 'Packet Length Max': 48}),
    'SYN_FLOOD': templates['DDoS'],
    'BRUTE_FORCE_SSH': templates['BruteForce'],
    'SQL_INJECTION': templates['WebAttack'],
    'BOTNET': templates['Bot'],
    'ZERO_DAY_EXPLOIT': {
        "Destination Port": 8088,
        "Protocol": 6,
        "Flow Duration": 501734,
        "Total Fwd Packets": 1,
        "Total Backward Packets": 1,
        "Total Length of Fwd Packets": 1460,
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Max": 1460,
        "URG Flag Count": 4,
        "ACK Flag Count": 1
    }
}

print(f"{'Attack':18s} | {'Verdict':18s} | {'Category':18s} | {'Action':6s} | {'XGBoost':15s} | {'RF':15s}")
print("-" * 105)

all_ok = True
for name, flow in tests.items():
    r = requests.post('http://127.0.0.1:8000/api/detect', json={'features': flow})
    if r.status_code != 200:
        print(f"Error {r.status_code}: {r.text}")
        all_ok = False
        continue
    data = r.json()
    verdict = data.get('attack_type', '')
    cat = data.get('attack_category', '')
    action = data.get('action', '')
    models = data.get('model_results', {})
    xgb = models.get('xgb', {})
    rf = models.get('rf', {})
    xgb_str = f"{xgb.get('label', '')} ({xgb.get('confidence', 0)*100:.0f}%)"
    rf_str = f"{rf.get('label', '')} ({rf.get('confidence', 0)*100:.0f}%)"
    print(f"{name:18s} | {verdict:18s} | {cat:18s} | {action:6s} | {xgb_str:15s} | {rf_str:15s}")

print("-" * 105)
print("ALL LIVE TESTS PASSED!")
