import sys, json, requests
sys.path.insert(0, ".")

d = json.load(open('frontend/src/pages/attackTemplates.json'))
tests = ['PortScan', 'DoS', 'DDoS', 'BruteForce', 'WebAttack', 'Bot', 'ZeroDay', 'BENIGN']

print(f"{'Template':12} | {'RF in UI':22} | {'XGB in UI':16} | {'Verdict':20}")
print("-" * 80)
for key in tests:
    r = requests.post('http://127.0.0.1:8000/api/detect', json={'features': d[key]}).json()
    rf = r.get('model_results', {}).get('rf', {})
    xgb = r.get('model_results', {}).get('xgb', {})
    rf_label = rf.get('label', '?')
    rf_type = rf.get('attack_type', '')
    rf_conf = rf.get('confidence', 0) * 100
    xgb_label = xgb.get('label', '?')
    xgb_conf = xgb.get('confidence', 0) * 100
    verdict = r.get('attack_type', '?')

    # What Detect.jsx shows for RF
    is_atk = rf.get('is_attack') or rf_label == 'ATTACK'
    if is_atk:
        if rf_type and rf_type not in ['ATTACK', 'BENIGN']:
            ui_rf = f"ATTACK ({rf_type}) {rf_conf:.0f}%"
        else:
            ui_rf = f"ATTACK {rf_conf:.0f}%"
    else:
        ui_rf = f"BENIGN {rf_conf:.0f}%"
    ui_xgb = f"{xgb_label} {xgb_conf:.0f}%"
    print(f"{key:12} | {ui_rf:22} | {ui_xgb:16} | {verdict}")
