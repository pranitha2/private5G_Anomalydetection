import argparse
import os
import logging
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# --- Feature Extraction ---
def extract_features_from_packet(packet):
    features = {
        'timestamp': float(packet.time),
        'src_ip': None,
        'dst_ip': None,
        'src_port': 0,
        'dst_port': 0,
        'protocol': 0,
        'packet_length': len(packet),
        'ip_flags': 0,
        'ip_ttl': 0,
        'tcp_flags': 0,
        'udp_length': 0,
        'icmp_type': -1,
        'icmp_code': -1,
        'dns_query': 0
    }

    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['protocol'] = packet[IP].proto
        features['ip_flags'] = int(packet[IP].flags)
        features['ip_ttl'] = packet[IP].ttl

        if TCP in packet:
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            flags_map = {'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16, 'U': 32, 'E': 64, 'C': 128}
            tcp_flag_sum = 0
            # Scapy flags can be like FlagValue("S") or FlagValue("SA")
            # str(packet[TCP].flags) converts it to string like "S" or "SA"
            for flag_char in str(packet[TCP].flags):
                tcp_flag_sum += flags_map.get(flag_char, 0)
            features['tcp_flags'] = tcp_flag_sum

            if packet.haslayer(DNS) and packet[DNS].qr == 0: # 0 for query
                features['dns_query'] = 1

        elif UDP in packet:
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
            features['udp_length'] = packet[UDP].len
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                features['dns_query'] = 1

        elif ICMP in packet:
            features['icmp_type'] = packet[ICMP].type
            features['icmp_code'] = packet[ICMP].code
    
    return features

def pcap_to_dataframe(pcap_file_path):
    if not os.path.exists(pcap_file_path):
        logging.error(f"PCAP file {pcap_file_path} not found.")
        return None

    logging.info(f"Processing PCAP file: {pcap_file_path}")
    packets_data = []
    try:
        packets = rdpcap(pcap_file_path)
        for packet_num, packet in enumerate(packets):
            try:
                packets_data.append(extract_features_from_packet(packet))
            except Exception as e_inner:
                logging.warning(f"Could not parse packet #{packet_num} in {pcap_file_path}: {e_inner}")
    except Exception as e:
        logging.error(f"Error reading or parsing PCAP file {pcap_file_path}: {e}")
        return None
    
    if not packets_data:
        logging.warning(f"No packets processed from {pcap_file_path}.")
        return pd.DataFrame()

    df = pd.DataFrame(packets_data)
    logging.info(f"Extracted {len(df)} packets into DataFrame from {pcap_file_path}.")
    return df

# --- Anomaly Detection ---
def detect_anomalies_isolation_forest(df, contamination=0.05, random_state=42):
    if df.empty or len(df) < 2:
        logging.warning("DataFrame is empty or too small for anomaly detection.")
        if not df.empty:
            df['is_anomaly'] = 0
        return df

    features_for_model = [
        'packet_length', 'protocol', 'src_port', 'dst_port',
        'ip_flags', 'ip_ttl', 'tcp_flags', 'udp_length',
        'icmp_type', 'icmp_code', 'dns_query', 'timestamp' # Added timestamp
    ]
    
    existing_features = [f for f in features_for_model if f in df.columns]
    if not existing_features:
        logging.error("No suitable features found for anomaly detection model.")
        df['is_anomaly'] = 0
        return df

    X = df[existing_features].copy()
    X.fillna(0, inplace=True)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    logging.info(f"Training Isolation Forest model with contamination={contamination} on {len(X_scaled)} samples and {len(existing_features)} features.")
    model = IsolationForest(contamination=contamination, random_state=random_state, n_estimators=100)
    model.fit(X_scaled)

    predictions = model.predict(X_scaled)
    df['is_anomaly'] = np.where(predictions == -1, 1, 0)
    
    num_anomalies = df['is_anomaly'].sum()
    logging.info(f"Anomaly detection complete. Found {num_anomalies} anomalies.")
    
    return df

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="PCAP Anomaly Detector using Isolation Forest")
    parser.add_argument("pcap_file", help="Path to the input PCAP file")
    parser.add_argument("output_csv", help="Path to save the output CSV file with anomaly labels")
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="The proportion of outliers in the data set (for Isolation Forest)"
    )
    args = parser.parse_args()

    logging.info(f"Starting anomaly detection for {args.pcap_file}")

    features_df = pcap_to_dataframe(args.pcap_file)

    if features_df is None or features_df.empty:
        logging.error("Feature extraction failed or produced no data. Exiting.")
        # Create an empty CSV with headers if output_csv is specified, to signal completion but no data
        try:
            headers = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
                       'packet_length', 'ip_flags', 'ip_ttl', 'tcp_flags', 'udp_length', 
                       'icmp_type', 'icmp_code', 'dns_query', 'is_anomaly']
            empty_df = pd.DataFrame(columns=headers)
            output_dir = os.path.dirname(args.output_csv)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            empty_df.to_csv(args.output_csv, index=False)
            logging.info(f"Empty results CSV saved to {args.output_csv} due to no data.")
        except Exception as e:
            logging.error(f"Failed to save empty CSV to {args.output_csv}: {e}")
        return

    results_df = detect_anomalies_isolation_forest(features_df, contamination=args.contamination)

    try:
        output_dir = os.path.dirname(args.output_csv)
        if output_dir and not os.path.exists(output_dir): # Ensure directory exists
            os.makedirs(output_dir)
            logging.info(f"Created output directory: {output_dir}")
        results_df.to_csv(args.output_csv, index=False)
        logging.info(f"Results with anomaly labels saved to {args.output_csv}")
    except Exception as e:
        logging.error(f"Failed to save CSV to {args.output_csv}: {e}")

if __name__ == "__main__":
    main()