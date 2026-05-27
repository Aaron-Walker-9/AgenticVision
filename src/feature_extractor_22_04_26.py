"""
windowed_feature_extractor.py
------------------------------------------------------------------------------
Time-based sliding-window feature engineering pipeline for XGBoost LLM
traffic fingerprinting via Inter-Token Timing (ITT) and packet IAT patterns.

Key design: windows are defined by TIME (seconds), not packet count.
This ensures each window represents the same observation period regardless
of packet rate -- critical for comparing slow vs fast LLM responses fairly.

Window strategy
---------------
  Each flow is sliced into overlapping time windows of width WINDOW_SEC,
  advancing by STRIDE_SEC (e.g. 1.0s window, 0.5s stride = 50% overlap).
  Both packet and token events falling within [t_start, t_end] are used.
  Windows with fewer than MIN_PKTS packets are skipped.

Feature categories (all scalar, XGBoost-ready)
-----------------------------------------------
  [A] Packet counts and byte statistics
  [B] Packet IAT statistics (mean, std, min, max, skew, kurt)
  [C] Packet IAT percentiles (p10..p95) + burstiness ratios
  [D] Packet IAT entropy (Shannon, normalised)
  [E] Packet IAT autocorrelation at lags 1-3 (rhythm fingerprint)
  [F] Burst detection (count, gap CV, fraction in-burst)
  [G] Backward (response) IAT features -- ITT proxy from packet layer
  [H] Byte growth linearity (R2, slope, residual std)
  [I] Token ITT statistics (if .tokens.json available)
  [J] Token ITT percentiles, entropy, autocorrelation, burst
  [K] Cross-signal features (bytes/token, IAT alignment ratio)
  [L] Delta features vs. previous window (trend signals)
  [M] Positional features (window index, elapsed time, normalised position)

Requirements
------------
    pip install scapy pandas scipy numpy pyarrow
"""

from __future__ import annotations

import json
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import entropy as scipy_entropy

warnings.filterwarnings("ignore")

# Force UTF-8 output so print() never raises UnicodeEncodeError on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

try:
    from scapy.all import IP, IPv6, TCP, UDP, Raw, rdpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: scapy not installed -- pip install scapy")


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class WindowConfig:
    # --- Time-based window parameters ----------------------------------------
    window_sec: float = 0.5         # width of each time window in seconds
    stride_sec: float = 0.1         # step between windows (0.1 = 20% overlap)
    min_pkts_per_window: int = 1    # skip windows with fewer packets than this
    min_tokens_per_window: int = 1  # min tokens to compute token features

    # --- Burst detection thresholds ------------------------------------------
    pkt_burst_gap_s: float = 0.10   # packet IAT > this separates bursts
    tok_burst_gap_s: float = 0.15   # token ITT > this separates token bursts

    # --- Autocorrelation lags ------------------------------------------------
    ac_lags: Tuple[int, ...] = (1, 2, 3)

    # --- I/O -----------------------------------------------------------------
    captures_dir: Path = Path("Datastore/raw_captures")
    output_csv: Path = Path("Datastore/processed_datasets/dataset_windowed.csv")
    output_parquet: Path = Path("Datastore/processed_datasets/dataset_windowed.parquet")


CFG = WindowConfig()

# =============================================================================
# LOW-LEVEL STATISTICAL HELPERS
# =============================================================================

def _safe_div(a: float, b: float, fallback: float = 0.0) -> float:
    return a / b if b != 0 else fallback


def _base_stats(arr: np.ndarray, prefix: str) -> Dict[str, float]:
    """mean, std, min, max, skew, kurtosis -- always returns all 6 keys."""
    if len(arr) == 0:
        return {f"{prefix}_{k}": 0.0
                for k in ("mean", "std", "min", "max", "skew", "kurt")}
    return {
        f"{prefix}_mean": round(float(np.mean(arr)), 6),
        f"{prefix}_std":  round(float(np.std(arr)), 6) if len(arr) > 1 else 0.0,
        f"{prefix}_min":  round(float(np.min(arr)), 6),
        f"{prefix}_max":  round(float(np.max(arr)), 6),
        f"{prefix}_skew": round(float(stats.skew(arr)), 4) if len(arr) > 2 else 0.0,
        f"{prefix}_kurt": round(float(stats.kurtosis(arr)), 4) if len(arr) > 3 else 0.0,
    }


def _percentile_features(arr: np.ndarray, prefix: str) -> Dict[str, float]:
    """p10..p95 + burstiness ratios + IQR. Always returns all keys."""
    _keys = ("p10", "p25", "p50", "p75", "p90", "p95",
             "p95_p50_ratio", "p75_p25_ratio", "iqr")
    if len(arr) == 0:
        return {f"{prefix}_{k}": 0.0 for k in _keys}
    p10, p25, p50, p75, p90, p95 = np.percentile(arr, [10, 25, 50, 75, 90, 95])
    return {
        f"{prefix}_p10": round(float(p10), 6),
        f"{prefix}_p25": round(float(p25), 6),
        f"{prefix}_p50": round(float(p50), 6),
        f"{prefix}_p75": round(float(p75), 6),
        f"{prefix}_p90": round(float(p90), 6),
        f"{prefix}_p95": round(float(p95), 6),
        # Upper-tail burstiness: how much bigger is p95 than the median?
        # High ratio = irregular token bursts (e.g. reasoning model pauses)
        f"{prefix}_p95_p50_ratio": round(_safe_div(p95, max(p50, 1e-9)), 4),
        # Spread: interquartile spread normalised by lower quartile
        f"{prefix}_p75_p25_ratio": round(_safe_div(p75, max(p25, 1e-9)), 4),
        f"{prefix}_iqr":           round(float(p75 - p25), 6),
    }


def _entropy_features(arr: np.ndarray, prefix: str,
                       bins: int = 20) -> Dict[str, float]:
    """
    Shannon entropy of the value histogram.
    High entropy = values spread across many bins (irregular).
    Low entropy = values clustered (regular rhythm).
    Always returns both keys.
    """
    if len(arr) < 2:
        return {f"{prefix}_entropy": 0.0, f"{prefix}_norm_entropy": 0.0}
    counts, _ = np.histogram(arr, bins=bins)
    counts = counts[counts > 0].astype(float)
    probs = counts / counts.sum()
    h = float(scipy_entropy(probs, base=2))
    h_max = float(np.log2(len(probs))) if len(probs) > 1 else 1.0
    return {
        f"{prefix}_entropy":      round(h, 4),
        f"{prefix}_norm_entropy": round(_safe_div(h, h_max), 4),
    }


def _autocorr(arr: np.ndarray, lag: int) -> float:
    """Pearson autocorrelation at a given lag. Returns 0 if undefined."""
    if len(arr) <= lag + 1:
        return 0.0
    x, y = arr[:-lag], arr[lag:]
    sx, sy = float(np.std(x)), float(np.std(y))
    if sx == 0 or sy == 0:
        return 0.0
    return round(float(np.corrcoef(x, y)[0, 1]), 4)


def _autocorr_features(arr: np.ndarray, prefix: str,
                        lags: Tuple[int, ...] = (1, 2, 3)) -> Dict[str, float]:
    """
    Autocorrelation at multiple lags.
    High AC at lag 1 = regular periodic delivery (e.g. fixed-rate streaming).
    Peak at lag 2-3 = chunked delivery with a characteristic chunk period.
    These patterns differ significantly between LLM providers.
    """
    return {f"{prefix}_ac_lag{lag}": _autocorr(arr, lag) for lag in lags}


def _burst_features(iats: np.ndarray, prefix: str,
                    gap_threshold: float = 0.1) -> Dict[str, float]:
    """
    Characterise bursts separated by gaps > gap_threshold seconds.
    Always returns all 3 keys so DataFrame columns are consistent.
    """
    if len(iats) == 0:
        return {
            f"{prefix}_burst_count":     0,
            f"{prefix}_burst_gap_cv":    0.0,
            f"{prefix}_frac_burst_pkts": 0.0,
        }
    gap_iats = iats[iats > gap_threshold]
    burst_count = int(len(gap_iats)) + 1
    burst_gap_cv = (
        _safe_div(float(np.std(gap_iats)), float(np.mean(gap_iats)))
        if len(gap_iats) > 1 else 0.0
    )
    frac_in_burst = float(np.sum(iats <= gap_threshold)) / len(iats)
    return {
        f"{prefix}_burst_count":     burst_count,
        f"{prefix}_burst_gap_cv":    round(burst_gap_cv, 4),
        f"{prefix}_frac_burst_pkts": round(frac_in_burst, 4),
    }


# =============================================================================
# ZERO-FILL HELPERS
# Ensures every window row has identical columns even when bwd or token
# events are absent -- critical for XGBoost which needs a fixed schema.
# =============================================================================

def _zero_bwd_iat_features(cfg: WindowConfig) -> Dict[str, float]:
    feats: Dict[str, float] = {}
    feats.update(_base_stats(np.array([]), "bwd_iat"))
    feats.update(_autocorr_features(np.array([]), "bwd_iat", cfg.ac_lags))
    feats.update(_burst_features(np.array([]), "bwd", cfg.pkt_burst_gap_s))
    return feats


def _zero_token_features(cfg: WindowConfig) -> Dict[str, float]:
    feats: Dict[str, float] = {"token_count": 0.0, "tok_rate": 0.0, "tok_iat_cv": 0.0}
    feats.update(_base_stats(np.array([]), "tok_iat"))
    feats.update(_percentile_features(np.array([]), "tok_iat"))
    feats.update(_entropy_features(np.array([]), "tok_iat"))
    feats.update(_autocorr_features(np.array([]), "tok_iat", cfg.ac_lags))
    feats.update(_burst_features(np.array([]), "tok", cfg.tok_burst_gap_s))
    return feats


def _zero_byte_growth_features() -> Dict[str, float]:
    return {
        "byte_growth_r2":           0.0,
        "byte_growth_slope":        0.0,
        "byte_growth_residual_std": 0.0,
    }


# =============================================================================
# PER-WINDOW FEATURE EXTRACTION
# =============================================================================

def extract_packet_window_features(
    pkt_times: np.ndarray,
    pkt_lens:  np.ndarray,
    fwd_mask:  np.ndarray,
    cfg: WindowConfig,
    t_start: float,
) -> Dict[str, float]:
    """
    Extract all scalar features from one TIME-BOUNDED window of packets.
    All arrays must already be sliced to [t_start, t_start + window_sec].
    """
    feats: Dict[str, float] = {}
    n = len(pkt_times)

    if n == 0:
        return feats

    # --- [A] Counts and byte totals ------------------------------------------
    n_fwd = int(np.sum(fwd_mask))
    n_bwd = int(np.sum(~fwd_mask))
    fwd_bytes = pkt_lens[fwd_mask]
    bwd_bytes = pkt_lens[~fwd_mask]

    feats["pkt_count"]          = n
    feats["fwd_count"]          = n_fwd
    feats["bwd_count"]          = n_bwd
    feats["fwd_bwd_pkt_ratio"]  = round(_safe_div(n_fwd, max(n_bwd, 1)), 4)
    feats["total_bytes"]        = int(np.sum(pkt_lens))
    feats["fwd_bytes"]          = int(np.sum(fwd_bytes))
    feats["bwd_bytes"]          = int(np.sum(bwd_bytes))
    feats["byte_ratio_bwd_fwd"] = round(_safe_div(float(np.sum(bwd_bytes)), float(max(np.sum(fwd_bytes), 1))), 4)
    feats["pkt_ratio_bwd_fwd"]  = round(_safe_div(n_bwd, max(n_fwd, 1)), 4)

    # Packet length distributions
    feats.update(_base_stats(pkt_lens,  "pktlen"))
    feats.update(_percentile_features(pkt_lens, "pktlen"))
    feats.update(_entropy_features(pkt_lens, "pktlen"))
    feats.update(_base_stats(fwd_bytes if len(fwd_bytes) > 0 else np.array([]), "fwd_pktlen"))
    feats.update(_base_stats(bwd_bytes if len(bwd_bytes) > 0 else np.array([]), "bwd_pktlen"))

    # --- [A] Throughput (normalised to fixed window width) -------------------
    # Using cfg.window_sec (not actual span) makes throughput comparable
    # across windows even if packets cluster at window edges
    feats["throughput_bps"]     = round(_safe_div(float(np.sum(pkt_lens)), cfg.window_sec), 2)
    feats["bwd_throughput_bps"] = round(_safe_div(float(np.sum(bwd_bytes)), cfg.window_sec), 2)

    # --- [B/C/D/E/F] Packet IAT features -------------------------------------
    iats = np.diff(np.sort(pkt_times)) if n > 1 else np.array([])
    feats.update(_base_stats(iats, "iat"))
    feats.update(_percentile_features(iats, "iat"))
    feats.update(_entropy_features(iats, "iat"))
    feats.update(_autocorr_features(iats, "iat", cfg.ac_lags))
    feats.update(_burst_features(iats, "pkt", cfg.pkt_burst_gap_s))

    # --- [G] Backward-only IAT (ITT proxy from packet layer) -----------------
    # Response packets give the best ITT proxy when no token file is available
    bwd_times = np.sort(pkt_times[~fwd_mask])
    if len(bwd_times) > 1:
        bwd_iats = np.diff(bwd_times)
        feats.update(_base_stats(bwd_iats, "bwd_iat"))
        feats.update(_autocorr_features(bwd_iats, "bwd_iat", cfg.ac_lags))
        feats.update(_burst_features(bwd_iats, "bwd", cfg.pkt_burst_gap_s))
    else:
        feats.update(_zero_bwd_iat_features(cfg))

    # --- [H] Cumulative byte growth linearity --------------------------------
    # R2 ~ 1.0 = smooth uniform streaming; low R2 = chunked bursty delivery
    if n > 3:
        cum_bytes = np.cumsum(pkt_lens).astype(float)
        t_rel = pkt_times - t_start   # relative to window start for stability
        if t_rel[-1] > 0:
            slope, intercept, r, _, _ = stats.linregress(t_rel, cum_bytes)
            residuals = cum_bytes - (slope * t_rel + intercept)
            feats["byte_growth_r2"]           = round(float(r ** 2), 4)
            feats["byte_growth_slope"]        = round(float(slope), 2)
            feats["byte_growth_residual_std"] = round(float(np.std(residuals)), 2)
        else:
            feats.update(_zero_byte_growth_features())
    else:
        feats.update(_zero_byte_growth_features())

    return feats


def extract_token_window_features(
    token_times: np.ndarray,
    cfg: WindowConfig,
) -> Dict[str, float]:
    """
    Extract ITT (Inter-Token Timing) features from one time window.
    token_times must already be sliced to the window boundaries.
    """
    feats: Dict[str, float] = {}
    n = len(token_times)
    feats["token_count"] = float(n)

    if n < 2:
        feats["tok_rate"]   = 0.0
        feats["tok_iat_cv"] = 0.0
        feats.update(_base_stats(np.array([]), "tok_iat"))
        feats.update(_percentile_features(np.array([]), "tok_iat"))
        feats.update(_entropy_features(np.array([]), "tok_iat"))
        feats.update(_autocorr_features(np.array([]), "tok_iat", cfg.ac_lags))
        feats.update(_burst_features(np.array([]), "tok", cfg.tok_burst_gap_s))
        return feats

    itts = np.diff(np.sort(token_times))

    feats.update(_base_stats(itts, "tok_iat"))
    feats.update(_percentile_features(itts, "tok_iat"))
    feats.update(_entropy_features(itts, "tok_iat"))
    feats.update(_autocorr_features(itts, "tok_iat", cfg.ac_lags))
    feats.update(_burst_features(itts, "tok", cfg.tok_burst_gap_s))

    # Token rate using fixed window width for cross-window comparability
    feats["tok_rate"] = round(_safe_div(float(n), cfg.window_sec), 2)

    # CV: low = metronomic (some providers use fixed-rate SSE)
    #     high = irregular chunking (reasoning pause then burst)
    feats["tok_iat_cv"] = round(
        _safe_div(float(np.std(itts)), float(np.mean(itts))), 4)

    return feats


# =============================================================================
# DELTA FEATURES  (window[n] - window[n-1])
# =============================================================================

DELTA_KEYS = [
    # Packet IAT trends
    "iat_mean", "iat_std", "iat_p50", "iat_p95", "iat_ac_lag1",
    # Backward IAT (response rhythm) trends
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_ac_lag1",
    # Byte-level trends
    "pktlen_mean", "pktlen_entropy", "throughput_bps",
    "byte_ratio_bwd_fwd", "byte_growth_r2", "byte_growth_residual_std",
    # Token ITT trends
    "tok_iat_mean", "tok_iat_std", "tok_iat_p50", "tok_iat_ac_lag1",
    "tok_rate", "tok_iat_cv",
]


import math
from typing import Dict, Optional

def compute_delta_features(
    current: Dict[str, float],
    previous: Optional[Dict[str, float]],) -> Dict[str, float]:

    deltas = {}

    for k in DELTA_KEYS:
        c = current.get(k)
        p = previous.get(k) if previous is not None else None

        # Handle missing values explicitly
        if c is None or p is None:
            deltas[f"delta_{k}"] = math.nan
        else:
            deltas[f"delta_{k}"] = float(c) - float(p)

    return deltas



# =============================================================================
# POSITIONAL FEATURES
# =============================================================================

def compute_positional_features(
    win_idx:             int,
    flow_start:          float,
    window_start:        float,
    flow_total_duration: float,
) -> Dict[str, float]:
    """
    Describe where this window sits within the overall flow.
    flow_position_norm correctly uses flow_total_duration (not window_start)
    as the denominator so it spans [0, 1] across the flow.
    """
    elapsed = float(window_start - flow_start)
    norm = round(_safe_div(elapsed, max(flow_total_duration, 1e-6)), 4)
    norm = min(norm, 1.0)
    return {
        "win_idx":            win_idx,
        "flow_elapsed_s":     round(elapsed, 4),
        "flow_position_norm": norm,
    }


# =============================================================================
# PCAP LOADER
# =============================================================================

@dataclass
class FlowData:
    times:        np.ndarray
    lengths:      np.ndarray
    fwd_mask:     np.ndarray
    tls_detected: bool
    duration:     float


def load_pcap_flow(pcap_path: Path) -> Optional[FlowData]:
    if not SCAPY_AVAILABLE:
        return None
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"  [ERR] Cannot read {pcap_path.name}: {e}")
        return None

    def ip_layer(pkt):
        if IP in pkt:   return pkt[IP]
        if IPv6 in pkt: return pkt[IPv6]
        return None

    first = next((p for p in packets if ip_layer(p) and TCP in p), None)
    if first is None:
        first = next((p for p in packets if ip_layer(p) and UDP in p), None)
    if first is None:
        return None

    ip0      = ip_layer(first)
    src_ip   = ip0.src
    src_port = first[TCP].sport if TCP in first else first[UDP].sport

    times, lengths, fwd_flags = [], [], []
    tls = False

    for pkt in packets:
        ipl = ip_layer(pkt)
        if ipl is None:
            continue
        if TCP not in pkt and UDP not in pkt:
            continue

        times.append(float(pkt.time))
        lengths.append(len(pkt))

        pkt_src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
        pkt_dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport

        fwd_flags.append(ipl.src == src_ip and pkt_src_port == src_port)

        if pkt_dst_port == 443 or pkt_src_port == 443:
            tls = True
        if Raw in pkt:
            raw = bytes(pkt[Raw])
            if len(raw) >= 2 and raw[0] == 0x16 and raw[1] == 0x03:
                tls = True

    if not times:
        return None

    order = np.argsort(times)
    t = np.array(times,   dtype=np.float64)[order]
    l = np.array(lengths, dtype=np.int32)[order]
    f = np.array(fwd_flags, dtype=bool)[order]

    return FlowData(times=t, lengths=l, fwd_mask=f,
                    tls_detected=tls, duration=float(t[-1] - t[0]))


# =============================================================================
# TIME-BASED SLIDING WINDOW ENGINE
# =============================================================================

def sliding_windows_for_flow(
    flow:        FlowData,
    token_times: Optional[np.ndarray],
    meta:        Dict,
    cfg:         WindowConfig,
) -> List[Dict]:
    """
    Slide a time window of width cfg.window_sec across the flow,
    stepping by cfg.stride_sec. Returns one feature dict per window.
    """
    rows: List[Dict] = []
    prev_pkt_feats: Optional[Dict] = None
    prev_tok_feats: Optional[Dict] = None

    flow_start = float(flow.times[0])
    flow_end   = float(flow.times[-1])
    flow_dur   = flow.duration

    w_start = flow_start
    win_idx = 0

    while w_start < flow_end:
        w_end = w_start + cfg.window_sec

        # Slice packets into this time window
        mask_pkt = (flow.times >= w_start) & (flow.times < w_end)
        t_win = flow.times[mask_pkt]
        l_win = flow.lengths[mask_pkt]
        f_win = flow.fwd_mask[mask_pkt]


        # [A-H] Packet features
        pkt_feats = extract_packet_window_features(t_win, l_win, f_win, cfg, w_start)
        pkt_feats["tls_detected"] = int(flow.tls_detected)

        # [M] Positional features
        pos_feats = compute_positional_features(win_idx, flow_start, w_start, flow_dur)

        # [L] Packet delta features
        pkt_delta = compute_delta_features(pkt_feats, prev_pkt_feats)
        # only update previous if this window had real data
        if len(t_win) >= cfg.min_pkts_per_window:
            prev_pkt_feats = pkt_feats.copy()

        # [I-J] Token ITT features aligned to the same time window
        if token_times is not None and len(token_times) > 0:
            mask_tok = (token_times >= w_start) & (token_times < w_end)
            tok_slice = token_times[mask_tok]
            if len(tok_slice) >= cfg.min_tokens_per_window:
                tok_feats = extract_token_window_features(tok_slice, cfg)
            else:
                tok_feats = _zero_token_features(cfg)
        else:
            tok_feats = _zero_token_features(cfg)

        tok_delta = compute_delta_features(tok_feats, prev_tok_feats)
        if tok_feats.get("token_count", 0) > 0:
            prev_tok_feats = tok_feats.copy()

        # [K] Cross-signal features
        cross_feats: Dict[str, float] = {}
        tok_rate = float(tok_feats.get("tok_rate", 0.0))
        tput     = float(pkt_feats.get("throughput_bps", 0.0))
        if tok_rate > 0 and tput > 0:
            cross_feats["bytes_per_token"] = round(_safe_div(tput, tok_rate), 2)
            cross_feats["iat_tok_pkt_ratio"] = round(
                _safe_div(
                    tok_feats.get("tok_iat_mean", 0.0),
                    pkt_feats.get("bwd_iat_mean", pkt_feats.get("iat_mean", 1.0))
                ), 4)

        # Labels
        row: Dict = {
            "session_id":     meta["session_id"],
            "label_llm":      meta["llm_name"],
            "label_model":    meta["model"],
            "label_workload": meta["workload"],
        }
        row.update(pos_feats)
        row.update(pkt_feats)
        row.update(tok_feats)
        row.update(pkt_delta)
        row.update(tok_delta)
        row.update(cross_feats)
        rows.append(row)

        w_start += cfg.stride_sec
        win_idx += 1

    return rows


# =============================================================================
# DATASET BUILDER
# =============================================================================

def build_windowed_dataset(cfg: WindowConfig = CFG) -> pd.DataFrame:

    json_files = sorted(
    p for p in cfg.captures_dir.glob("*.json")
    if not p.name.endswith(".tokens.json")
)

    if not json_files:
        print(f"No .json files found in {cfg.captures_dir}")
        return pd.DataFrame()

    print(f"Processing {len(json_files)} session(s)  "
          f"[window={cfg.window_sec}s  stride={cfg.stride_sec}s]\n")

    all_rows: List[Dict] = []

    for meta_path in json_files:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        if not isinstance(meta, dict):
            print(f"[SKIP] Not metadata: {meta_path.name}")
            continue
        
        if meta.get("error"):
            print(f"  [SKIP] Errored session: {meta['session_id']}")
            continue

        pcap_stem = Path(meta["pcap_path"]).stem   # original filename without extension
        pcap_path = (meta_path.parent / (pcap_stem + "_filtered.pcap")).resolve()

        # fallback to original pcap if filtered version doesn't exist
        if not pcap_path.exists():
            print(f"  [WARN] No filtered PCAP found, falling back to original: {pcap_stem}.pcap")
            pcap_path = (meta_path.parent / meta["pcap_path"]).resolve()

        flow = load_pcap_flow(pcap_path)
        if flow is None:
            print(f"  [SKIP] Unreadable PCAP: {pcap_path.name}")
            continue

        # Load token timestamps (optional)
        token_times: Optional[np.ndarray] = None
        
        # token files always use the original name (no _filtered suffix)
        pcap_stem_original = pcap_path.stem.replace("_filtered", "")
        token_path = pcap_path.parent / (pcap_stem_original + ".tokens.json")

        if token_path.exists():
            try:
                with open(token_path, encoding="utf-8") as f:
                    series = json.load(f)
                t_rel = np.array([x["t_rel"] for x in series], dtype=np.float64)
                if len(t_rel) > 0:
                    # Align relative token times to absolute packet timestamps
                    token_times = t_rel + flow.times[0]
            except Exception as e:
                print(f"  [WARN] Token file error {token_path.name}: {e}")
        else:
            print(f"  [WARN] No token file: {token_path.name}")

        rows = sliding_windows_for_flow(flow, token_times, meta, cfg)
        all_rows.extend(rows)

        tok_info = (f"{len(token_times)} tokens"
                    if token_times is not None else "no tokens")
        print(f"  {meta['session_id']}  [{meta['llm_name']}]  "
              f"[{meta['workload']}]  "
              f"{flow.duration:.1f}s  {tok_info}  ->  {len(rows)} windows")

    if not all_rows:
        return pd.DataFrame()

    df = pd.DataFrame(all_rows)

    # Fill NaN from conditionally absent features with 0
    df = df.fillna(0.0)

    # Cast feature columns to float32
    id_cols = {c for c in df.columns
               if c.startswith(("label_", "session_", "win_idx"))}
    feat_cols = [c for c in df.columns if c not in id_cols]
    df[feat_cols] = df[feat_cols].astype("float32")

    print(f"\nDataset: {df.shape[0]} windows x {df.shape[1]} columns")
    print(f"Avg windows per session: {df.shape[0] / max(len(json_files), 1):.1f}")
    return df


def save_dataset(df: pd.DataFrame, cfg: WindowConfig = CFG) -> None:
    df.to_csv(cfg.output_csv, index=False)
    print(f"Saved CSV     -> {cfg.output_csv.resolve()}")
    try:
        df.to_parquet(cfg.output_parquet, index=False)
        print(f"Saved Parquet -> {cfg.output_parquet.resolve()}")
    except ImportError:
        print("pyarrow not installed; skipping Parquet")


# =============================================================================
# FEATURE SUMMARY UTILITY
# =============================================================================

def print_feature_groups(df: pd.DataFrame) -> None:
    id_cols = {"session_id", "win_idx", "label_llm", "label_model", "label_workload"}
    feat_cols = [c for c in df.columns if c not in id_cols]

    groups = {
        "Counts / bytes":      [c for c in feat_cols
                                 if any(x in c for x in ("count", "bytes", "ratio", "tls"))],
        "Packet len stats":    [c for c in feat_cols if "pktlen" in c],
        "IAT base stats":      [c for c in feat_cols
                                 if c.startswith("iat_") and "_ac_" not in c
                                 and "_p" not in c and "entropy" not in c],
        "IAT percentiles":     [c for c in feat_cols
                                 if "iat_p" in c
                                 and not c.startswith(("tok", "bwd", "delta"))],
        "IAT entropy":         [c for c in feat_cols
                                 if "iat_entropy" in c
                                 and not c.startswith(("tok", "bwd", "delta"))],
        "IAT autocorr":        [c for c in feat_cols
                                 if "iat_ac_lag" in c
                                 and not c.startswith(("tok", "bwd", "delta"))],
        "Burst":               [c for c in feat_cols if "burst" in c],
        "Bwd IAT (ITT proxy)": [c for c in feat_cols if c.startswith("bwd_")],
        "Throughput / timing": [c for c in feat_cols
                                 if any(x in c for x in ("throughput", "duration", "elapsed"))],
        "Byte growth":         [c for c in feat_cols if "byte_growth" in c],
        "Token ITT":           [c for c in feat_cols
                                 if c.startswith("tok_") and not c.startswith("delta")],
        "Delta features":      [c for c in feat_cols if c.startswith("delta_")],
        "Cross-signal":        [c for c in feat_cols
                                 if any(x in c for x in ("bytes_per_token", "iat_tok"))],
        "Positional":          [c for c in feat_cols
                                 if any(x in c for x in ("flow_elapsed", "flow_position", "win_idx"))],
    }

    print("\n -- Feature Groups ------------------------------------------")
    total = 0
    for group, cols in groups.items():
        if cols:
            sample = str(cols[:3]).rstrip("]") + ("..." if len(cols) > 3 else "]")
            print(f"  {group:25s}  {len(cols):3d}  {sample}")
            total += len(cols)
    uncategorised = len(feat_cols) - total
    if uncategorised:
        print(f"  {'(uncategorised)':25s}  {uncategorised:3d}")
    print(f"  {'TOTAL':25s}  {len(feat_cols):3d}")
    print("------------------------------------------------------------")


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    cfg = WindowConfig(
        window_sec=0.5,            # 0.1-second observation window
        stride_sec=0.1,            # 20% overlap
        min_pkts_per_window=1,
        min_tokens_per_window=1,
    )

    df = build_windowed_dataset(cfg)

    if not df.empty:
        save_dataset(df, cfg)
        print_feature_groups(df)

        if "label_llm" in df.columns:
            print("\n -- Windows per LLM -----------------------------------------")
            summary = (df.groupby("label_llm")["session_id"]
                         .agg(windows="count", sessions=pd.Series.nunique))
            print(summary.to_string())
    else:
        print("No data to save.")