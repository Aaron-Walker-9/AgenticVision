import pandas as pd
import subprocess
import os
from pathlib import Path
from src.features.extract_flows import FlowExtractor
from src.features.aggregate_flows_to_session import aggregate_flows_to_session


### Run 'python -m src.pipeline.pcapng_to_features' in bash/terminal to run data processing pipeline

#Remove payload information from raw files
session_df = pd.read_csv("Datastore/Metadata/labels.csv")
raw_file_names = session_df["Session_ID"]

def strip_payload(files):
    editcap_path = r"C:\Program Files\Wireshark\editcap.exe" #initalise editcap
    
    for raw_file in files:
        input_file = rf"G:\AV_Datastore\raw\{raw_file}.pcapng"
        output_file = rf"G:\AV_Datastore\payload_removed\{raw_file}.pcapng"
        
        # Make sure input file exists
        if not os.path.exists(input_file):
            print(f"File not found: {input_file}")
            continue
        
        # Run editcap to truncate packets to headers only
        subprocess.run([
            editcap_path,
            "-s", "128",  # truncate packets to 128 bytes
            input_file,
            output_file
        ], check=True)
        print(f"Processed: {raw_file}")

strip_payload(raw_file_names)

def process_all_pcaps():
    """End-to-end pipeline: PCAP → Flows → Session Features."""
    
    # Load metadata
    metadata = pd.read_csv("Datastore\Metadata\labels.csv")
    
    print(f"Processing {len(metadata)} sessions...")
    
    for idx, row in metadata.iterrows():
        session_id = row['Session_ID']
        pcap_file = fr"G:\AV_Datastore\payload_removed\{session_id}.pcapng" #import payload stripped file
        flow_file = fr"G:\AV_Datastore\processed\flows\{session_id}_flows.parquet"
        
        print(f"\n[{idx+1}/{len(metadata)}] {session_id}")
        
        # Check if PCAP exists
        if not Path(pcap_file).exists():
            print(f"  PCAP not found: {pcap_file}")
            continue
        
        # Step 1: Extract flows (if not already done)
        if not Path(flow_file).exists():
            print(f"  → Extracting flows...")
            extractor = FlowExtractor(pcap_file)
            df_flows = extractor.compute_flow_features()
            df_flows.to_parquet(flow_file, index=False)
            print(f" {len(df_flows)} flows extracted")
        else:
            print(f" Flows already extracted")
            df_flows = pd.read_parquet(flow_file)
        
    # Step 2: Aggregate all sessions
    print("\n" + "="*50)
    print("Aggregating flows to session-level features...")
    
    session_features_list = []
    
    for _, row in metadata.iterrows():
        session_id = row['Session_ID']
        flow_file = rf"G:\AV_Datastore\processed\flows\{session_id}_flows.parquet"
        
        if not Path(flow_file).exists():
            continue
        
        flow_df = pd.read_parquet(flow_file)
        session_features = aggregate_flows_to_session(flow_df, session_id, row)
        session_features_list.append(session_features)
    
    # Create final dataset
    df_sessions = pd.DataFrame(session_features_list)
    
    # Add binary AI label
    df_sessions['is_ai'] = df_sessions['Workload_Type'].str.contains('AI').astype(int)
    
    df_sessions.to_parquet("G:\AV_Datastore\processed\session_features.parquet", index=False)
    
    print(f"\n Final dataset: {len(df_sessions)} sessions, {len(df_sessions.columns)} features")
    print(f"   Saved to: data/processed/session_features.parquet")
    
    # Summary stats
    print("\nDataset Summary:")
    print(f"  AI sessions:     {df_sessions['is_ai'].sum()}")
    print(f"  Non-AI sessions: {(df_sessions['is_ai'] == 0).sum()}")
    print(f"  Total flows:     {df_sessions['num_flows'].sum():.0f}")
    print(f"  Total traffic:   {df_sessions['total_bytes'].sum() / 1e9:.2f} GB")
    
    return df_sessions

if __name__ == "__main__":
    df = process_all_pcaps()