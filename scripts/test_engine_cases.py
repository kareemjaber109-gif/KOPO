from src.ml.detection_engine import DetectionEngine
engine = DetectionEngine.get_instance()

test_cases = [
    ('BENIGN', {'Protocol': 6, 'Flow Duration': 1500000, 'Total Fwd Packets': 10, 'Total Backward Packets': 10, 'Fwd Packet Length Max': 512, 'Flow Bytes/s': 6826.67, 'Flow Packets/s': 13.33, 'SYN Flag Count': 1, 'ACK Flag Count': 10, 'Avg Packet Size': 512}),
    ('HTTP_FLOOD', {'Protocol': 6, 'Flow Duration': 500000, 'Total Fwd Packets': 8000, 'Total Backward Packets': 50, 'Fwd Packet Length Max': 1460, 'Flow Bytes/s': 23360000, 'Flow Packets/s': 16100, 'SYN Flag Count': 1, 'ACK Flag Count': 50, 'Avg Packet Size': 1460}),
    ('SYN_FLOOD', {'Protocol': 6, 'Flow Duration': 100000, 'Total Fwd Packets': 5000, 'Total Backward Packets': 0, 'Fwd Packet Length Max': 60, 'Flow Bytes/s': 3000000, 'Flow Packets/s': 50000, 'SYN Flag Count': 5000, 'ACK Flag Count': 0, 'Avg Packet Size': 60}),
    ('UDP_FLOOD', {'Protocol': 17, 'Flow Duration': 50000, 'Total Fwd Packets': 10000, 'Total Backward Packets': 0, 'Fwd Packet Length Max': 1024, 'Flow Bytes/s': 204800000, 'Flow Packets/s': 200000, 'SYN Flag Count': 0, 'ACK Flag Count': 0, 'Avg Packet Size': 1024}),
    ('PORT_SCAN', {'Protocol': 6, 'Flow Duration': 1500000, 'Total Fwd Packets': 150, 'Total Backward Packets': 0, 'Fwd Packet Length Max': 0, 'Flow Bytes/s': 0, 'Flow Packets/s': 100, 'SYN Flag Count': 150, 'ACK Flag Count': 0, 'Avg Packet Size': 0}),
    ('BRUTE_FORCE_SSH', {'Protocol': 6, 'Flow Duration': 30000000, 'Total Fwd Packets': 1000, 'Total Backward Packets': 1000, 'Fwd Packet Length Max': 300, 'Flow Bytes/s': 20000, 'Flow Packets/s': 66.67, 'SYN Flag Count': 1, 'ACK Flag Count': 2000, 'Avg Packet Size': 300}),
    ('SQL_INJECTION', {'Protocol': 6, 'Flow Duration': 4000000, 'Total Fwd Packets': 50, 'Total Backward Packets': 50, 'Fwd Packet Length Max': 1460, 'Flow Bytes/s': 36500, 'Flow Packets/s': 25, 'SYN Flag Count': 1, 'ACK Flag Count': 50, 'Avg Packet Size': 1460})
]

for name, flow in test_cases:
    res = engine.predict(flow)
    rf_lbl = res["model_results"]["rf"]["label"]
    xgb_lbl = res["model_results"]["xgb"]["label"]
    print(f"{name:15} -> Attack={res['is_attack']!s:5} | Type={res['attack_type']:18} | Cat={res['attack_category']:15} | Conf={res['confidence']:.3f} | RF={rf_lbl} | XGB={xgb_lbl}")
