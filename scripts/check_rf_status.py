import sys, json
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine

d = json.load(open('frontend/src/pages/attackTemplates.json'))
e = DetectionEngine.get_instance()

tests = ['PortScan', 'DoS', 'DDoS', 'BruteForce', 'WebAttack', 'Bot', 'ZeroDay', 'BENIGN']
print(f"{'Template':12} | {'RF Label':20} | {'RF Conf':8} | {'XGB Label':14} | {'XGB Conf':8} | {'Verdict':20} | Done?")
print("-" * 110)
for key in tests:
    flow = d[key]
    res = e.predict(flow)
    rf = res['model_results'].get('rf', {})
    xgb = res['model_results'].get('xgb', {})
    rf_label = rf.get('label', '?')
    rf_type = rf.get('attack_type', '?')
    rf_conf = rf.get('confidence', 0) * 100
    xgb_label = xgb.get('label', '?')
    xgb_conf = xgb.get('confidence', 0) * 100
    verdict = res['attack_type']
    is_attack = res['is_attack']

    # For RF: if label is ATTACK show ATTACK(type), if BENIGN show BENIGN
    if rf_label == 'ATTACK' and rf_type not in ['ATTACK', 'BENIGN']:
        rf_display = f"ATTACK({rf_type})"
    elif rf_label == 'ATTACK':
        rf_display = "ATTACK"
    else:
        rf_display = "BENIGN"

    expected_attack = key != 'BENIGN'
    rf_correct = (rf_label == 'ATTACK') == expected_attack
    done = "✓ OK" if rf_correct else "✗ RF says BENIGN on ATTACK"
    print(f"{key:12} | {rf_display:20} | {rf_conf:6.1f}%  | {xgb_label:14} | {xgb_conf:6.1f}%  | {verdict:20} | {done}")
