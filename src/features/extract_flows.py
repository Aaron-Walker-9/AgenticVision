

from scapy.all import rdpcap
from collections import defaultdict
import pandas as pd
import numpy as np
from datetime import datetime

class FlowExtractor:
    """Extract flow-level statistics from PCAP files."""
    
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.flows = defaultdict(lambda: {
            'packets': [],
            'bytes': [],
            'timestamps': [],
            'directions': []  # 0 = forward, 1 = backward
        })
        
    def extract_flows(self):
        """Parse PCAP and group packets into flows."""
        
        print(f"Reading: {self.pcap_path}")
        packets = rdpcap(self.pcap_path)
        
        # First pass: identify local IP (most common source)
        src_ips = [pkt[1].src for pkt in packets if pkt.haslayer('IP')]
        from collections import Counter
        local_ip = Counter(src_ips).most_common(1)[0][0]
        print(f"Detected local IP: {local_ip}")
        
        # Second pass: group into flows
        for pkt in packets:
            if not pkt.haslayer('IP'):
                continue
                
            # Extract 5-tuple
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst
            
            # Get transport layer info
            if pkt.haslayer('TCP'):
                proto = 'TCP'
                src_port = pkt['TCP'].sport
                dst_port = pkt['TCP'].dport
            elif pkt.haslayer('UDP'):
                proto = 'UDP'
                src_port = pkt['UDP'].sport
                dst_port = pkt['UDP'].dport
            else:
                continue
            
            # Normalize flow direction (always local -> remote)
            if src_ip == local_ip:
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                direction = 0  # forward (upload)
            else:
                flow_key = (dst_ip, src_ip, dst_port, src_port, proto)
                direction = 1  # backward (download)
            
            # Add packet to flow
            self.flows[flow_key]['packets'].append(pkt)
            self.flows[flow_key]['bytes'].append(len(pkt))
            self.flows[flow_key]['timestamps'].append(float(pkt.time))
            self.flows[flow_key]['directions'].append(direction)
        
        print(f"Identified {len(self.flows)} unique flows")
        return self.flows
    
    def compute_flow_features(self):
        """Compute statistical features for each flow."""
        
        if not self.flows:
            self.extract_flows()
        
        flow_features = []
        
        for flow_key, flow_data in self.flows.items():
            src_ip, dst_ip, src_port, dst_port, proto = flow_key
            
            packets = flow_data['packets']
            byte_sizes = np.array(flow_data['bytes'])
            timestamps = np.array(flow_data['timestamps'])
            directions = np.array(flow_data['directions'])
            
            # Basic flow info
            features = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': proto,
            }
            
            # Flow-level statistics
            features['num_packets'] = len(packets)
            features['total_bytes'] = byte_sizes.sum()
            features['duration'] = timestamps.max() - timestamps.min()
            
            # Avoid division by zero
            if features['duration'] > 0:
                features['throughput_bps'] = (features['total_bytes'] * 8) / features['duration']
            else:
                features['throughput_bps'] = 0
            
            # Packet size statistics
            features['bytes_mean'] = byte_sizes.mean()
            features['bytes_std'] = byte_sizes.std()
            features['bytes_min'] = byte_sizes.min()
            features['bytes_max'] = byte_sizes.max()
            features['bytes_median'] = np.median(byte_sizes)
            
            # Inter-arrival times
            if len(timestamps) > 1:
                iats = np.diff(timestamps)
                features['iat_mean'] = iats.mean()
                features['iat_std'] = iats.std()
                features['iat_min'] = iats.min()
                features['iat_max'] = iats.max()
                features['iat_median'] = np.median(iats)
            else:
                features['iat_mean'] = 0
                features['iat_std'] = 0
                features['iat_min'] = 0
                features['iat_max'] = 0
                features['iat_median'] = 0
            
            # Burstiness (coefficient of variation)
            if features['iat_mean'] > 0:
                features['burstiness'] = features['iat_std'] / features['iat_mean']
            else:
                features['burstiness'] = 0
            
            # Directionality
            forward_packets = (directions == 0).sum()
            backward_packets = (directions == 1).sum()
            
            features['forward_packets'] = forward_packets
            features['backward_packets'] = backward_packets
            
            forward_bytes = byte_sizes[directions == 0].sum()
            backward_bytes = byte_sizes[directions == 1].sum()
            
            features['forward_bytes'] = forward_bytes
            features['backward_bytes'] = backward_bytes
            
            # Upload/Download ratio
            if backward_bytes > 0:
                features['ul_dl_ratio'] = forward_bytes / backward_bytes
            else:
                features['ul_dl_ratio'] = float('inf') if forward_bytes > 0 else 0
            
            # Direction changes (measure of interactivity)
            if len(directions) > 1:
                direction_changes = np.diff(directions) != 0
                features['direction_changes'] = direction_changes.sum()
            else:
                features['direction_changes'] = 0
            
            # Packet size entropy (diversity of packet sizes)
            from scipy.stats import entropy
            if len(byte_sizes) > 1:
                value_counts = np.bincount(byte_sizes)
                probabilities = value_counts / len(byte_sizes)
                features['size_entropy'] = entropy(probabilities)
            else:
                features['size_entropy'] = 0
            
            flow_features.append(features)
        
        return pd.DataFrame(flow_features)

# Usage
def process_pcap_to_flows(pcap_path, output_path):
    """Convert PCAP to flow-level features."""
    
    extractor = FlowExtractor(pcap_path)
    df_flows = extractor.compute_flow_features()
    
    # Save as Parquet
    df_flows.to_parquet(output_path, index=False)
    print(f"Saved {len(df_flows)} flows to {output_path}")
    
    return df_flows

# Example
if __name__ == "__main__":
    #Local test
    pcap_file = r"G:\AV_Datastore\payload_removed\20260204_1222_Web_Browsing_PC_Baseline.pcapng"
    output_file = r"G:\AV_Datastore\processed\flows\20260204_1222_Web_Browsing_PC_Baseline.parquet"
    
    df = process_pcap_to_flows(pcap_file, output_file)
    print(df)
