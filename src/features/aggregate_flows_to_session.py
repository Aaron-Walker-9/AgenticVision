import pandas as pd

def aggregate_flows_to_session(flow_df, session_id, metadata):
    """Aggregate all flows in a session into session-level features."""
    
    session_features = {}
    
    # Session metadata
    session_features['Session_ID'] = session_id
    session_features['Workload_Type'] = metadata['Workload_Type']
    session_features['User_Profile'] = metadata['User_Profile']
    
    # Flow count
    session_features['num_flows'] = len(flow_df)
    
    # Total traffic
    session_features['total_packets'] = flow_df['num_packets'].sum()
    session_features['total_bytes'] = flow_df['total_bytes'].sum()
    session_features['total_forward_bytes'] = flow_df['forward_bytes'].sum()
    session_features['total_backward_bytes'] = flow_df['backward_bytes'].sum()
    
    # Session-level UL/DL ratio
    if session_features['total_backward_bytes'] > 0:
        session_features['session_ul_dl_ratio'] = (
            session_features['total_forward_bytes'] / session_features['total_backward_bytes']
        )
    else:
        session_features['session_ul_dl_ratio'] = 0
    
    # Average flow statistics
    session_features['avg_flow_bytes'] = flow_df['total_bytes'].mean()
    session_features['avg_flow_duration'] = flow_df['duration'].mean()
    session_features['avg_flow_throughput'] = flow_df['throughput_bps'].mean()
    
    # Flow distribution statistics
    session_features['flow_bytes_std'] = flow_df['total_bytes'].std()
    session_features['flow_bytes_max'] = flow_df['total_bytes'].max()
    session_features['flow_bytes_min'] = flow_df['total_bytes'].min()
    
    # Dominant flow percentage (largest flow as % of total)
    max_flow_bytes = flow_df['total_bytes'].max()
    session_features['dominant_flow_pct'] = (max_flow_bytes / session_features['total_bytes']) * 100
    
    # Temporal statistics (aggregate)
    session_features['avg_iat_mean'] = flow_df['iat_mean'].mean()
    session_features['avg_burstiness'] = flow_df['burstiness'].mean()
    session_features['total_direction_changes'] = flow_df['direction_changes'].sum()
    
    # Protocol distribution
    if 'protocol' in flow_df.columns:
        tcp_flows = (flow_df['protocol'] == 'TCP').sum()
        session_features['tcp_flow_ratio'] = tcp_flows / len(flow_df)
    
    return session_features

# Process all sessions
def create_session_dataset():
    """Create final dataset with one row per session."""
    
    metadata = pd.read_csv("E:Datastore\Metadata\labels.csv")
    
    session_features_list = []
    
    for _, row in metadata.iterrows():
        session_id = row['Session_ID']
        
        # Load flow-level data for this session
        flow_file = rf"G:\AV_Datastore\processed\flows\{session_id}_flows.parquet"
        
        try:
            flow_df = pd.read_parquet(flow_file)
        except FileNotFoundError:
            print(f"Missing flow file: {flow_file}")
            continue
        
        # Aggregate to session
        session_features = aggregate_flows_to_session(flow_df, session_id, row)
        session_features_list.append(session_features)
    
    # Create final dataset
    df_sessions = pd.DataFrame(session_features_list)
    df_sessions.to_parquet(r"G:\AV_Datastore\processed\sessions\session_features.parquet", index=False)
    
    print(f"Created dataset with {len(df_sessions)} sessions")
    return df_sessions

if __name__ == "__main__":
    df = create_session_dataset()
    print(df)