"""Generate statistical Unknown/Anomaly flows (CICFlowMeter-style) for testing KOPO IDS.

Supports three modes:
  1. api   (default): send generated anomaly flows directly to POST /api/detect
  2. csv             : export generated flows (optionally with an 'Anomaly' label)
  3. scapy           : send paced ICMP packets to loopback 127.0.0.1 only

Examples:
  python scripts/generate_anomaly_traffic.py --mode api --count 10
  python scripts/generate_anomaly_traffic.py --mode csv --count 500 --output data/processed/anomaly_flows.csv --include-label
  python scripts/generate_anomaly_traffic.py --mode scapy --count 24 --interval 0.0075
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import time
import urllib.request
from pathlib import Path


def generate_anomaly_flow(seed: int | None = None) -> dict[str, float | int]:
    """Generate CICFlowMeter-compatible features representing non-signature statistical anomalies."""
    if seed is not None:
        random.seed(seed)

    # Non-standard protocols (other/ICMP/GRE/ESP) and non-service ports
    protocol = random.choice([0, 1, 47, 50])
    dst_port = random.choice([0, 0, 0, 7, 9])

    # Suspiciously short burst or elongated duration
    duration = random.choice([
        random.randint(50, 500),
        random.randint(500_000, 2_000_000),
    ])

    # Heavily asymmetric / one-way flow
    fwd_packets = random.randint(3, 60)
    backward_packets = random.choice([0, 0, 0, 1, 2])

    style = random.choice(["uniform", "bimodal", "tiny_noise"])
    if style == "uniform":
        pkt_len = random.choice([1000, 1500, 2000])
        fwd_lengths = [pkt_len] * fwd_packets
    elif style == "bimodal":
        small = random.randint(1, 20)
        big = random.randint(1400, 1500)
        fwd_lengths = [random.choice([small, big]) for _ in range(fwd_packets)]
    else:
        fwd_lengths = [random.randint(1, 64) for _ in range(fwd_packets)]

    bwd_lengths = [0] * backward_packets
    total_fwd_len = sum(fwd_lengths)
    total_bwd_len = sum(bwd_lengths)

    iat_mean = duration / max(fwd_packets - 1, 1) if duration > 0 and fwd_packets > 1 else 0.0
    if random.random() < 0.5:
        iat_std = 0.0
        iat_max = iat_min = iat_mean
    else:
        iat_std = iat_mean * random.uniform(2.0, 10.0)
        iat_max = iat_mean + iat_std * 2.0
        iat_min = max(0.0, iat_mean - iat_std)

    dur_sec = duration / 1_000_000 if duration else 0.0
    flow_bytes_s = (total_fwd_len + total_bwd_len) / dur_sec if dur_sec else 0.0
    flow_pkts_s = (fwd_packets + backward_packets) / dur_sec if dur_sec else 0.0

    fwd_mean = total_fwd_len / fwd_packets if fwd_packets else 0.0
    fwd_std = math.sqrt(sum((x - fwd_mean) ** 2 for x in fwd_lengths) / fwd_packets) if fwd_packets else 0.0
    bwd_mean = total_bwd_len / backward_packets if backward_packets else 0.0
    bwd_std = math.sqrt(sum((x - bwd_mean) ** 2 for x in bwd_lengths) / backward_packets) if backward_packets else 0.0

    return {
        "Destination Port": dst_port,
        "Protocol": protocol,
        "Flow Duration": duration,
        "Total Fwd Packets": fwd_packets,
        "Total Backward Packets": backward_packets,
        "Total Length of Fwd Packets": total_fwd_len,
        "Total Length of Bwd Packets": total_bwd_len,
        "Fwd Packet Length Max": max(fwd_lengths) if fwd_lengths else 0,
        "Fwd Packet Length Min": min(fwd_lengths) if fwd_lengths else 0,
        "Fwd Packet Length Mean": round(fwd_mean, 2),
        "Fwd Packet Length Std": round(fwd_std, 2),
        "Bwd Packet Length Max": max(bwd_lengths) if bwd_lengths else 0,
        "Bwd Packet Length Min": min(bwd_lengths) if bwd_lengths else 0,
        "Bwd Packet Length Mean": round(bwd_mean, 2),
        "Bwd Packet Length Std": round(bwd_std, 2),
        "Flow Bytes/s": round(flow_bytes_s, 2),
        "Flow Packets/s": round(flow_pkts_s, 2),
        "Flow IAT Mean": round(iat_mean, 2),
        "Flow IAT Std": round(iat_std, 2),
        "Flow IAT Max": round(iat_max, 2),
        "Flow IAT Min": round(iat_min, 2),
        "Fwd IAT Total": duration,
        "Fwd IAT Mean": round(iat_mean, 2),
        "Fwd IAT Std": round(iat_std, 2),
        "Fwd IAT Max": round(iat_max, 2),
        "Fwd IAT Min": round(iat_min, 2),
        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
    }


def run_api_mode(api_url: str, count: int, seed_start: int) -> None:
    """Send generated anomaly flows to KOPO /api/detect and print detection summary."""
    endpoint = api_url.rstrip("/") + "/api/detect"
    flagged = 0
    anomaly_scores: list[float] = []

    for i in range(count):
        flow = generate_anomaly_flow(seed=seed_start + i)
        payload = json.dumps({
            "source_ip": f"10.99.{i // 250}.{(i % 250) + 1}",
            "dest_ip": "10.0.0.10",
            "features": flow,
        }).encode("utf-8")
        req = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            res = json.loads(resp.read().decode("utf-8"))

        is_anom = bool(res.get("is_anomaly"))
        score = res.get("anomaly_score")
        if score is not None:
            anomaly_scores.append(float(score))
        if res.get("is_attack") or is_anom:
            flagged += 1
        print(
            f"[{i + 1}/{count}] proto={flow['Protocol']} port={flow['Destination Port']} "
            f"-> verdict={res.get('attack_type')} action={res.get('action')} "
            f"anomaly={score} is_anomaly={is_anom}"
        )

    mean_score = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0.0
    print(f"\nSummary: {flagged}/{count} flagged | mean anomaly_score={mean_score:.4f}")


def run_csv_mode(output: Path, count: int, seed_start: int, include_label: bool) -> None:
    """Write generated anomaly flows to a CSV file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = None
        for i in range(count):
            row = generate_anomaly_flow(seed=seed_start + i)
            if include_label:
                row["Label"] = "Anomaly"
            if writer is None:
                writer = csv.DictWriter(f, fieldnames=list(row.keys()))
                writer.writeheader()
            writer.writerow(row)
    print(f"Wrote {count} anomaly flows to {output}")


def run_scapy_mode(target: str, count: int, payload_bytes: int, interval_sec: float) -> None:
    """Send paced uniform ICMP packets strictly to loopback for safe local replay."""
    if target not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("Refusing non-loopback target for safety. Use 127.0.0.1 for local testing.")

    from scapy.all import ICMP, IP, Raw, send  # type: ignore

    payload = Raw(b"\x00" * max(0, payload_bytes))
    print(f"Sending {count} ICMP packets to {target} ({payload_bytes}B payload, every {interval_sec * 1000:.2f} ms)")
    start = time.perf_counter()
    for i in range(count):
        pkt = IP(dst=target) / ICMP(type=8, id=0x1234, seq=i) / payload
        send(pkt, verbose=False)
        next_t = start + (i + 1) * interval_sec
        sleep = next_t - time.perf_counter()
        if sleep > 0:
            time.sleep(sleep)
    elapsed = time.perf_counter() - start
    print(f"Sent {count} packets in {elapsed:.4f}s ({count / max(elapsed, 1e-6):.2f} pkt/s)")


def main() -> None:
    parser = argparse.ArgumentParser(description="KOPO Statistical Anomaly Flow Generator")
    parser.add_argument("--mode", choices=["api", "csv", "scapy"], default="api")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output", type=Path, default=Path("data/processed/anomaly_flows.csv"))
    parser.add_argument("--include-label", action="store_true")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--payload-bytes", type=int, default=1972)
    parser.add_argument("--interval", type=float, default=0.0075195)
    args = parser.parse_args()

    if args.mode == "api":
        run_api_mode(args.api_url, args.count, args.seed)
    elif args.mode == "csv":
        run_csv_mode(args.output, args.count, args.seed, args.include_label)
    else:
        run_scapy_mode(args.target, args.count, args.payload_bytes, args.interval)


if __name__ == "__main__":
    main()
