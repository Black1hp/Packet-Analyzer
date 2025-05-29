# ml_portscan_detector.py

import json
import time
import pandas as pd
import joblib # Requires scikit-learn
from collections import defaultdict
from datetime import datetime, timezone
import argparse
import os

# --- Configuration (matches user's script) ---
target_ip = "192.168.1.12" # Default, can be overridden by args if implemented
scan_threshold = 5  # Number of unique ports hit from a source IP
time_interval = 5  # Seconds for the detection window

# --- Globals ---
connection_attempts = defaultdict(list) # Stores (port, timestamp_float) tuples for each src_ip
model = None
scaler = None

# --- Load ML Model and Scaler ---
MODEL_PATH = "portscan_detector_model.pkl"
SCALER_PATH = "scaler.pkl"

def load_model_and_scaler():
    global model, scaler
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print(f"[*] Successfully loaded model ({MODEL_PATH}) and scaler ({SCALER_PATH}).")
    except FileNotFoundError:
        print(f"[!] Error: Model ({MODEL_PATH}) or scaler ({SCALER_PATH}) not found.")
        print("[!] ML-based predictions will be disabled. Alerts will be based on threshold only if enabled.")
    except Exception as e:
        print(f"[!] Error loading model/scaler: {e}")
        print("[!] ML-based predictions will be disabled. Alerts will be based on threshold only if enabled.")

# --- Feature Engineering (adapted from user's script) ---
def build_features(src_ip):
    """Builds features for the ML model based on connection attempts."""
    attempts_in_window = connection_attempts[src_ip]
    packet_count = len(attempts_in_window)
    pps = packet_count / time_interval if time_interval > 0 else 0

    features = {
        'Flow Duration': 0,
        'Total Fwd Packets': packet_count,
        'Total Backward Packets': 0,
        'Total Length of Fwd Packets': 0,
        'Total Length of Bwd Packets': 0,
        'Fwd Packet Length Max': 0,
        'Bwd Packet Length Max': 0,
        'Fwd Packet Length Min': 0,
        'Flow Bytes/s': 0,
        'Flow Packets/s': pps
    }
    
    df = pd.DataFrame([features])
    if scaler:
        try:
            scaled_features = scaler.transform(df)
            return scaled_features
        except Exception as e:
            print(f"[!] Error scaling features for {src_ip}: {e}")
            return df.values # Return numpy array if error
    else:
        return df.values

# --- EVE JSON Processing ---
def parse_eve_timestamp(timestamp_str):
    """Parses Suricata's EVE JSON timestamp string to a float (Unix timestamp)."""
    try:
        dt_obj = datetime.fromisoformat(timestamp_str.replace("+0000", "+00:00"))
        return dt_obj.timestamp()
    except ValueError as e:
        print(f"[!] Error parsing timestamp '{timestamp_str}': {e}. Using current time.")
        return time.time()

def process_eve_event(eve_line_str):
    """Processes a single line (event) from Suricata's EVE JSON log."""
    global connection_attempts, target_ip # Ensure target_ip is accessible
    try:
        event = json.loads(eve_line_str)
    except json.JSONDecodeError:
        # print(f"[!] Failed to decode JSON: {eve_line_str.strip()}") # Can be noisy
        return

    event_type = event.get("event_type")
    timestamp_str = event.get("timestamp")
    if not timestamp_str:
        return
    
    current_timestamp_float = parse_eve_timestamp(timestamp_str)

    src_ip_evt = event.get("src_ip")
    dest_ip_evt = event.get("dest_ip")
    dest_port_evt = event.get("dest_port")
    proto_evt = event.get("proto")

    if proto_evt != "TCP" or dest_ip_evt != target_ip or not src_ip_evt or not dest_port_evt:
        return

    is_syn_packet = False
    tcp_info = event.get("tcp", {})
    if event_type == "flow":
        if tcp_info.get("syn") or "S" in tcp_info.get("tcp_flags_ts", "") or "S" in tcp_info.get("flags", ""):
            is_syn_packet = True
    elif event_type == "alert":
        if tcp_info.get("syn") or "S" in tcp_info.get("tcp_flags", "") or "S" in tcp_info.get("flags", ""):
            is_syn_packet = True
    
    if is_syn_packet:
        connection_attempts[src_ip_evt] = [
            (p, t) for p, t in connection_attempts[src_ip_evt]
            if t > current_timestamp_float - time_interval
        ]
        connection_attempts[src_ip_evt].append((dest_port_evt, current_timestamp_float))

        if len(connection_attempts[src_ip_evt]) >= scan_threshold:
            features_scaled = build_features(src_ip_evt)
            prediction = 0 
            if model and scaler:
                try:
                    prediction = model.predict(features_scaled)[0]
                except Exception as e:
                    print(f"[!] Error during prediction for {src_ip_evt}: {e}")
            else: 
                pass 

            if prediction == 1:
                ports_hit = sorted(list(set([p for p, t in connection_attempts[src_ip_evt]])))
                print(f"\n[ML-ALERT] Port Scan Detected from {src_ip_evt} (Prediction: {prediction})")
                print(f"           Target: {target_ip}, Ports hit: {ports_hit}\n")
            
            connection_attempts[src_ip_evt] = []

# --- File Tailing Logic ---
def follow(thefile):
    thefile.seek(0, os.SEEK_END)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

# --- Main Execution ---
def run_test_sample():
    global target_ip # Allow modification for sample test if needed
    # Potentially set a different target_ip for sample data if it's not 169.254.0.21
    # For now, it uses the global target_ip
    print("[*] Running with internal sample EVE logs.")
    sample_eve_logs = [
        '{"timestamp": "2024-05-13T10:00:00.000000+0000", "event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "169.254.0.21", "dest_port": 80, "proto": "TCP", "tcp": {"syn": true, "flags_ts": "S"}}',
        '{"timestamp": "2024-05-13T10:00:00.500000+0000", "event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "169.254.0.21", "dest_port": 443, "proto": "TCP", "tcp": {"syn": true, "flags_ts": "S"}}',
        '{"timestamp": "2024-05-13T10:00:01.000000+0000", "event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "169.254.0.21", "dest_port": 22, "proto": "TCP", "tcp": {"syn": true, "flags_ts": "S"}}',
        '{"timestamp": "2024-05-13T10:00:02.000000+0000", "event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "169.254.0.21", "dest_port": 21, "proto": "TCP", "tcp": {"syn": true, "flags_ts": "S"}}',
        '{"timestamp": "2024-05-13T10:00:03.000000+0000", "event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "169.254.0.21", "dest_port": 8080, "proto": "TCP", "tcp": {"syn": true, "flags_ts": "S"}}',
        '{"timestamp": "2024-05-13T10:00:03.500000+0000", "event_type": "flow", "src_ip": "10.0.0.2", "dest_ip": "169.254.0.21", "dest_port": 80, "proto": "TCP", "tcp": {"syn": true, "flags_ts": "S"}}',
        '{"timestamp": "2024-05-13T10:00:06.000000+0000", "event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "169.254.0.21", "dest_port": 3389, "proto": "TCP", "tcp": {"syn": true, "flags_ts": "S"}}',
    ]
    for log_line in sample_eve_logs:
        process_eve_event(log_line)
        time.sleep(0.1) # Simulate time passing slightly
    print("[*] ML Port Scan Detector internal sample test run finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML Port Scan Detector for Suricata EVE logs.")
    parser.add_argument("--log-file", help="Path to Suricata EVE JSON log file to monitor (tails by default).")
    parser.add_argument("--test-sample", action="store_true", help="Run with internal sample EVE logs instead of tailing a file.")
    parser.add_argument("--batch-process", action="store_true", help="Process the --log-file from beginning to end once, then exit (do not tail).")
    parser.add_argument("--target-ip", help=f"Target IP to monitor for scans. Default: {target_ip}")

    args = parser.parse_args()

    if args.target_ip:
        target_ip = args.target_ip
        print(f"[*] Target IP overridden by command line: {target_ip}")

    load_model_and_scaler()
    print(f"[*] ML Port Scan Detector started. Monitoring for scans targeting {target_ip}.")
    print(f"[*] Scan Threshold: {scan_threshold} SYN packets to distinct ports in {time_interval} seconds from a single source.")

    if args.test_sample:
        run_test_sample()
    elif args.log_file:
        if args.batch_process:
            print(f"[*] Batch processing log file: {args.log_file}")
            try:
                with open(args.log_file, 'r') as f:
                    for line in f:
                        process_eve_event(line)
                print(f"[*] Finished batch processing: {args.log_file}")
            except FileNotFoundError:
                print(f"[!] Log file not found: {args.log_file}")
            except Exception as e:
                print(f"[!] An error occurred during batch processing: {e}")
        else:
            print(f"[*] Tailing log file: {args.log_file}")
            try:
                with open(args.log_file, 'r') as f:
                    for line in follow(f):
                        process_eve_event(line)
            except FileNotFoundError:
                print(f"[!] Log file not found: {args.log_file}")
                print(f"[!] You can create a dummy file or use --test-sample to run with internal data.")
            except KeyboardInterrupt:
                print("\n[*] ML Port Scan Detector stopped by user.")
            except Exception as e:
                print(f"[!] An error occurred: {e}")
    else:
        print("[!] No log file specified and --test-sample not used. Exiting.")
        print("[!] Use --log-file <path> to specify a log to process or tail, or --test-sample.")

