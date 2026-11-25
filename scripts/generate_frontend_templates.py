import json

vflows = json.load(open('data/models/verified_attack_flows.json'))

# Canonical 69 -> 77 UI mapping / aliases
# The 77 fields include:
# Destination Port, Protocol, Flow Duration, Total Fwd Packets, Total Backward Packets,
# Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min,
# Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min,
# Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean,
# Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max,
# Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags,
# Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s,
# Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std,
# Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count,
# ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size,
# Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length.1, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk,
# Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets,
# Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward,
# act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min,
# Idle Mean, Idle Std, Idle Max, Idle Min

def to_77_dict(flow_69, default_port=80):
    f = dict(flow_69)
    port = f.get('Destination Port', default_port)
    f['Destination Port'] = port
    f['Protocol'] = f.get('Protocol', 6.0)
    f['Total Length of Fwd Packets'] = f.get('Fwd Packets Length Total', 0.0)
    f['Total Length of Bwd Packets'] = f.get('Bwd Packets Length Total', 0.0)
    f['Min Packet Length'] = f.get('Packet Length Min', 0.0)
    f['Max Packet Length'] = f.get('Packet Length Max', f.get('Fwd Packet Length Max', 0.0))
    f['Average Packet Size'] = f.get('Avg Packet Size', 0.0)
    f['Bwd PSH Flags'] = 0.0
    f['Bwd URG Flags'] = 0.0
    f['Fwd Header Length.1'] = f.get('Fwd Header Length', 40.0)
    f['Fwd Avg Bytes/Bulk'] = 0.0
    f['Fwd Avg Packets/Bulk'] = 0.0
    f['Fwd Avg Bulk Rate'] = 0.0
    f['Bwd Avg Bytes/Bulk'] = 0.0
    f['Bwd Avg Packets/Bulk'] = 0.0
    f['Bwd Avg Bulk Rate'] = 0.0
    f['Init_Win_bytes_forward'] = f.get('Init Fwd Win Bytes', 8192.0)
    f['Init_Win_bytes_backward'] = f.get('Init Bwd Win Bytes', 0.0)
    f['act_data_pkt_fwd'] = f.get('Fwd Act Data Packets', max(0.0, f.get('Total Fwd Packets', 1.0) - 1.0))
    f['min_seg_size_forward'] = f.get('Fwd Seg Size Min', 20.0)
    return f

templates = {}

# 1. PortScan
t_ps = to_77_dict(vflows['PortScan'], default_port=445)
t_ps['Destination Port'] = 445
templates['PortScan'] = t_ps

# 2. DoS
t_dos = to_77_dict(vflows['DoS'], default_port=80)
t_dos['Destination Port'] = 80
templates['DoS'] = t_dos

# 3. DDoS
t_ddos = to_77_dict(vflows['DDoS'], default_port=80)
t_ddos['Destination Port'] = 80
templates['DDoS'] = t_ddos

# 4. BruteForce
t_bf = to_77_dict(vflows['BruteForce'], default_port=22)
t_bf['Destination Port'] = 22
templates['BruteForce'] = t_bf

# 5. WebAttack
t_wa = to_77_dict(vflows['WebAttack'], default_port=80)
t_wa['Destination Port'] = 80
templates['WebAttack'] = t_wa

# 6. Bot
t_bot = to_77_dict(vflows['Bot'], default_port=6667)
t_bot['Destination Port'] = 6667
templates['Bot'] = t_bot

# 7. ZeroDay (Explicit Anomalous Vector)
t_zd = to_77_dict(vflows['BENIGN'], default_port=8088)
t_zd['Destination Port'] = 8088
t_zd['Protocol'] = 6.0
t_zd['Flow Duration'] = 501734.0
t_zd['Total Fwd Packets'] = 1.0
t_zd['Total Backward Packets'] = 1.0
t_zd['URG Flag Count'] = 4.0
t_zd['ACK Flag Count'] = 1.0
t_zd['Fwd Packet Length Max'] = 1460.0
t_zd['Max Packet Length'] = 1460.0
t_zd['Init_Win_bytes_forward'] = 1024.0
t_zd['Init_Win_bytes_backward'] = 1024.0
t_zd['Init Fwd Win Bytes'] = 1024.0
t_zd['Init Bwd Win Bytes'] = 1024.0
templates['ZeroDay'] = t_zd

# 8. BENIGN
t_benign = to_77_dict(vflows['BENIGN'], default_port=443)
t_benign['Destination Port'] = 443
t_benign['Protocol'] = 6.0
t_benign['Init_Win_bytes_forward'] = 8192.0
t_benign['Init_Win_bytes_backward'] = 172.0
t_benign['Init Fwd Win Bytes'] = 8192.0
t_benign['Init Bwd Win Bytes'] = 172.0
t_benign['PSH Flag Count'] = 1.0
templates['BENIGN'] = t_benign

with open('frontend/src/pages/attackTemplates.json', 'w') as out:
    json.dump(templates, out, indent=2)

print("Saved frontend/src/pages/attackTemplates.json successfully!")
print("Template keys:", list(templates.keys()))
