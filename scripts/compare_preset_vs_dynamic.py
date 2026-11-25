import sys
sys.path.insert(0, ".")
import json
from scripts.test_all_subtypes import generate_attack_flow

with open("data/models/realistic_presets.json", "r") as f:
    presets = json.load(f)

# Compare Port Scan
preset_ps = presets["Port Scan"]
dyn_ps = generate_attack_flow("PORT_SCAN")

print("=== PORT SCAN: Preset vs Dynamic ===")
for k in preset_ps:
    val_preset = preset_ps[k]
    val_dyn = dyn_ps.get(k, "MISSING")
    if val_preset != val_dyn:
        print(f"  {k:<30}: Preset={val_preset:<15} | Dynamic={val_dyn}")

# Compare DoS Attack
preset_dos = presets["DoS Attack"]
dyn_dos = generate_attack_flow("HTTP_FLOOD")

print("\n=== DoS ATTACK: Preset vs Dynamic ===")
for k in preset_dos:
    val_preset = preset_dos[k]
    val_dyn = dyn_dos.get(k, "MISSING")
    if val_preset != val_dyn:
        print(f"  {k:<30}: Preset={val_preset:<15} | Dynamic={val_dyn}")

# Compare DDoS Attack
preset_ddos = presets["DDoS Attack"]
dyn_ddos = generate_attack_flow("SYN_FLOOD")

print("\n=== DDoS ATTACK: Preset vs Dynamic ===")
for k in preset_ddos:
    val_preset = preset_ddos[k]
    val_dyn = dyn_ddos.get(k, "MISSING")
    if val_preset != val_dyn:
        print(f"  {k:<30}: Preset={val_preset:<15} | Dynamic={val_dyn}")
