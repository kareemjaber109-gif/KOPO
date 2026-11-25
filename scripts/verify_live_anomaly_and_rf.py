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

print(f"{'Attack Name':17s} | {'Verdict':16s} | {'RF (Attack/Norm)':18s} | {'XGBoost':15s} | {'ISO':10s} | {'AE Anom':10s} | {'Votes':7s}")
print("-" * 115)

for name, flow in tests.items():
    r = requests.post('http://127.0.0.1:8000/api/detect', json={'features': flow})
    if r.status_code != 200:
        print(f"Error {r.status_code}: {r.text}")
        continue
    data = r.json()
    verdict = data.get('attack_type', '')
    models = data.get('model_results', {})
    rf = models.get('rf', {})
    xgb = models.get('xgb', {})
    iso = models.get('iso', {})
    ae = models.get('anomaly_ensemble', {})
    votes = f"{data.get('ensemble_votes', {}).get('attack')}/{data.get('ensemble_votes', {}).get('total')}"

    rf_disp = f"{rf.get('label')} ({rf.get('attack_type', '')}) {rf.get('confidence', 0)*100:.0f}%" if rf.get('is_attack') else f"BENIGN {rf.get('confidence', 0)*100:.0f}%"
    xgb_disp = f"{xgb.get('label')} {xgb.get('confidence', 0)*100:.0f}%"
    iso_disp = f"{iso.get('label')} {iso.get('confidence', 0)*100:.0f}%"
    ae_disp = f"{ae.get('label')} {ae.get('confidence', 0)*100:.0f}%"

    print(f"{name:17s} | {verdict:16s} | {rf_disp:18s} | {xgb_disp:15s} | {iso_disp:10s} | {ae_disp:10s} | {votes:7s}")
