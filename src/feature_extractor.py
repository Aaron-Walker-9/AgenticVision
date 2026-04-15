"""
feature_extractor.py
---------------------
Parses every .pcap + .json pair in the captures/ directory and
extracts per-flow network statistics into a flat CSV/Parquet dataset
suitable for machine-learning classifiers.

Features extracted per session:
  - Packet count (total, fwd, bwd)
  - Byte count (total, fwd, bwd)
  - Inter-arrival times (mean, std, min, max, skew)
  - Packet length statistics (mean, std, min, max)
  - Flow duration
  - Throughput (bytes/sec)
  - Burst statistics (packet bursts > 1 MTU gap)
  - TLS handshake presence flag
  - First-response latency (proxy: time to first bwd packet)
  - Response-to-request byte ratio

Requirements:
    pip install scapy pandas scipy pyarrow
"""

import json
import warnings
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from scipy import stats

warnings.filterwarnings("ignore")

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: scapy not installed. Install with: pip install scapy")

CAPTURES_DIR = Path("src/captures")
OUTPUT_CSV = Path("dataset.csv")
OUTPUT_PARQUET = Path("dataset.parquet")


# ─────────────────────────────────────────────────────────────────────────────
# PCAP FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def safe_stats(arr: List[float]) -> Dict[str, float]:
    """Return mean/std/min/max/skew for a list, handling edge cases."""
    if not arr:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "skew": 0.0}
    a = np.array(arr, dtype=float)
    return {
        "mean": float(np.mean(a)),
        "std": float(np.std(a)) if len(a) > 1 else 0.0,
        "min": float(np.min(a)),
        "max": float(np.max(a)),
        "skew": float(stats.skew(a)) if len(a) > 2 else 0.0,
    }


def extract_pcap_features(pcap_path: Path) -> Optional[Dict]:
    """
    Parse a PCAP and return a flat dict of flow statistics.
    Returns None if the pcap is empty or unreadable.
    """
    if not SCAPY_AVAILABLE:
        return None
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as exc:
        print(f"  Could not read {pcap_path.name}: {exc}")
        return None

    if len(packets) == 0:
        return None

    # Separate forward (request) and backward (response) packets
    # Heuristic: the first packet's src/sport defines the "forward" direction
    first_pkt = next((p for p in packets if IP in p and TCP in p), None)
    if first_pkt is None:
        return None

    src_ip = first_pkt[IP].src
    src_port = first_pkt[TCP].sport

    times = []
    fwd_lens, bwd_lens = [], []
    fwd_times, bwd_times = [], []
    tls_seen = False
    first_bwd_time = None

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        t = float(pkt.time)
        length = len(pkt)
        times.append(t)

        is_fwd = (pkt[IP].src == src_ip and pkt[TCP].sport == src_port)
        if is_fwd:
            fwd_lens.append(length)
            fwd_times.append(t)
        else:
            bwd_lens.append(length)
            bwd_times.append(t)
            if first_bwd_time is None:
                first_bwd_time = t

        # TLS detection: port 443 or TLS record header (0x16 0x03)
        if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
            tls_seen = True
        if Raw in pkt:
            raw = bytes(pkt[Raw])
            if len(raw) >= 2 and raw[0] == 0x16 and raw[1] == 0x03:
                tls_seen = True

    if not times:
        return None

    times_sorted = sorted(times)
    duration = times_sorted[-1] - times_sorted[0] if len(times_sorted) > 1 else 0.0

    # Inter-arrival times
    iats = [times_sorted[i+1] - times_sorted[i]
            for i in range(len(times_sorted) - 1)]

    all_lens = fwd_lens + bwd_lens
    total_bytes = sum(all_lens)
    throughput = total_bytes / duration if duration > 0 else 0.0

    # First response latency
    first_resp_latency = (first_bwd_time - times_sorted[0]) if first_bwd_time else 0.0

    # Byte ratio response/request
    byte_ratio = sum(bwd_lens) / max(sum(fwd_lens), 1)

    # Burst count: gaps > 0.1s separate bursts
    burst_count = 1
    for iat in iats:
        if iat > 0.1:
            burst_count += 1

    iat_s = safe_stats(iats)
    pkt_s = safe_stats(all_lens)
    fwd_s = safe_stats(fwd_lens)
    bwd_s = safe_stats(bwd_lens)

    return {
        # Packet counts
        "total_packets": len(all_lens),
        "fwd_packets": len(fwd_lens),
        "bwd_packets": len(bwd_lens),
        # Byte counts
        "total_bytes": total_bytes,
        "fwd_bytes": sum(fwd_lens),
        "bwd_bytes": sum(bwd_lens),
        # Flow timing
        "flow_duration_s": round(duration, 6),
        "throughput_bps": round(throughput, 2),
        "first_response_latency_s": round(first_resp_latency, 6),
        # IAT statistics
        "iat_mean": round(iat_s["mean"], 6),
        "iat_std": round(iat_s["std"], 6),
        "iat_min": round(iat_s["min"], 6),
        "iat_max": round(iat_s["max"], 6),
        "iat_skew": round(iat_s["skew"], 4),
        # Packet length statistics
        "pktlen_mean": round(pkt_s["mean"], 2),
        "pktlen_std": round(pkt_s["std"], 2),
        "pktlen_min": pkt_s["min"],
        "pktlen_max": pkt_s["max"],
        "pktlen_skew": round(pkt_s["skew"], 4),
        # Forward/backward length stats
        "fwd_pktlen_mean": round(fwd_s["mean"], 2),
        "fwd_pktlen_std": round(fwd_s["std"], 2),
        "bwd_pktlen_mean": round(bwd_s["mean"], 2),
        "bwd_pktlen_std": round(bwd_s["std"], 2),
        # Derived
        "byte_ratio_bwd_fwd": round(byte_ratio, 4),
        "burst_count": burst_count,
        "tls_detected": int(tls_seen),
    }
    
def extract_token_features(token_series):
    if len(token_series) < 2:
        return {
            "token_mean_iat": 0,
            "token_std_iat": 0,
            "token_bursts": 0
        }

    times = [x["t_rel"] for x in token_series]

    iats = [times[i] - times[i-1] for i in range(1, len(times))]

    burst_threshold = 0.2
    bursts = sum(1 for dt in iats if dt > burst_threshold)

    return {
        "token_mean_iat": float(np.mean(iats)),
        "token_std_iat": float(np.std(iats)),
        "token_min_iat": float(np.min(iats)),
        "token_max_iat": float(np.max(iats)),
        "token_bursts": bursts,
        "token_count": len(token_series),
    }
    


# ─────────────────────────────────────────────────────────────────────────────
# DATASET BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_dataset(captures_dir: Path = CAPTURES_DIR) -> pd.DataFrame:
    """
    Walk captures_dir, pair each .json metadata file with its .pcap,
    extract features, and return a labelled DataFrame.
    """
    rows = []
    json_files = sorted(captures_dir.glob("*.json"))

    if not json_files:
        print(f"No .json metadata files found in {captures_dir}")
        return pd.DataFrame()

    print(f"Processing {len(json_files)} session(s)...")

    for meta_path in json_files:
        with open(meta_path) as f:
            meta = json.load(f)

        pcap_path = Path(meta["pcap_path"]).resolve()
        
        if not pcap_path.exists():
            print(f"  [SKIP] PCAP not found: {pcap_path}")
            continue
        
        if meta.get("error"):
            print(f"  [SKIP] Session had error: {meta['session_id']}")
            continue

        flow_features = extract_pcap_features(pcap_path)

        if flow_features is None:
            print(f"  [SKIP] Empty/unreadable PCAP: {pcap_path.name}")
            continue


        # ── TOKEN FEATURE LOADING ─────────────────────────

        token_path = pcap_path.with_suffix(".tokens.json")

        token_features = {}
        if token_path.exists():
            try:
                with open(token_path, "r") as f:
                    token_series = json.load(f)

                token_features = extract_token_features(token_series)

            except Exception as exc:
                print(f"  [SKIP] Token file unreadable: {token_path.name} ({exc})")
                token_features = {}
        else:
            print(f"  [WARN] Missing token file: {token_path.name}")
        
        
        
        if flow_features is None:
            print(f"  [SKIP] Empty/unreadable PCAP: {pcap_path.name}")
            continue

        row = {
            # Labels
            "session_id": meta["session_id"],
            "label_llm": meta["llm_name"],
            "label_model": meta["model"],
            "label_workload": meta["workload"],
            "label_expected_tokens": meta["expected_tokens"],
            # Application-level ground truth (use as sanity check, not features)
            "meta_latency_s": meta["latency_seconds"],
            "meta_resp_words": meta["response_tokens_approx"],
            "meta_timestamp": meta["timestamp_utc"],
        }
        row.update(flow_features)
        row.update(token_features)
        rows.append(row)
        print(f"{meta['session_id']} [{meta['llm_name']}] [{meta['workload']}]")

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    print(f"\nDataset shape: {df.shape}")
    return df


def save_dataset(df: pd.DataFrame) -> None:
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved CSV -> {OUTPUT_CSV.resolve()}")
    try:
        df.to_parquet(OUTPUT_PARQUET, index=False)
        print(f"Saved Parquet -> {OUTPUT_PARQUET.resolve()}")
    except ImportError:
        print("pyarrow not installed; skipping Parquet output")


if __name__ == "__main__":
    df = build_dataset()
    if not df.empty:
        save_dataset(df)
        print("\nFeature columns:")
        feature_cols = [c for c in df.columns if not c.startswith(("label_", "meta_", "session_"))]
        for col in feature_cols:
            print(f"  {col}")
    else:
        print("No data to save.")
