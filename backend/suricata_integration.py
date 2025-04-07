import json
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
from datetime import datetime
import os
import sys
from dateutil import parser as date_parser
import argparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class SuricataLogHandler(FileSystemEventHandler):
    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url
        self.last_position = 0

    def parse_timestamp(self, timestamp_str):
        try:
            # Parse ISO format timestamp to datetime object
            dt = date_parser.parse(timestamp_str)
            # Convert to Unix timestamp (float)
            return dt.timestamp()
        except Exception as e:
            logging.error(f"Error parsing timestamp {timestamp_str}: {e}")
            return 0

    def process_line(self, line):
        try:
            data = json.loads(line)
            if 'event_type' in data and data['event_type'] == 'flow':
                # Get timestamps from the flow data
                flow = data.get('flow', {})
                start_time = flow.get('start')
                end_time = flow.get('end')
                
                # Convert timestamps to Unix timestamps
                flow_start = self.parse_timestamp(start_time) if start_time else 0
                flow_end = self.parse_timestamp(end_time) if end_time else 0
                
                # Map Suricata flow data to our format
                flow_data = {
                    'IPV4_SRC_ADDR': data.get('src_ip'),
                    'L4_SRC_PORT': int(data.get('src_port', 0)),
                    'IPV4_DST_ADDR': data.get('dest_ip'),
                    'L4_DST_PORT': int(data.get('dest_port', 0)),
                    'PROTOCOL': data.get('proto', '').upper(),
                    'L7_PROTO': data.get('app_proto', 'UNKNOWN').upper(),
                    'IN_BYTES': int(data.get('flow', {}).get('bytes_toserver', 0)),
                    'IN_PKTS': int(data.get('flow', {}).get('pkts_toserver', 0)),
                    'OUT_BYTES': int(data.get('flow', {}).get('bytes_toclient', 0)),
                    'OUT_PKTS': int(data.get('flow', {}).get('pkts_toclient', 0)),
                    'FLOW_DURATION_MILLISECONDS': max((flow_end - flow_start) * 1000, 0),
                    'TCP_FLAGS': data.get('tcp', {}).get('tcp_flags', 'N/A'),
                    'DNS_QUERY_TYPE': data.get('dns', {}).get('type'),
                    'DNS_QUERY_ID': data.get('dns', {}).get('id'),
                    'DNS_TTL_ANSWER': data.get('dns', {}).get('ttl'),
                    'IS_IPV6': ':' in str(data.get('src_ip', '')) or ':' in str(data.get('dest_ip', '')),
                }

                # Handle multicast and special addresses
                src_ip = str(data.get('src_ip', ''))
                dst_ip = str(data.get('dest_ip', ''))
                is_multicast = (
                    src_ip.startswith('ff02:') or 
                    dst_ip.startswith('ff02:') or 
                    dst_ip.startswith('224.') or 
                    dst_ip.startswith('239.')
                )
                
                # Improve protocol detection
                if flow_data['L7_PROTO'] == 'UNKNOWN' or flow_data['L7_PROTO'] == 'FAILED':
                    # Handle common multicast services
                    if flow_data['L4_SRC_PORT'] == 5353 or flow_data['L4_DST_PORT'] == 5353:
                        flow_data['L7_PROTO'] = 'MDNS'
                    elif flow_data['L4_SRC_PORT'] == 138 or flow_data['L4_DST_PORT'] == 138:
                        flow_data['L7_PROTO'] = 'NETBIOS'
                    elif is_multicast:
                        flow_data['L7_PROTO'] = 'MULTICAST'
                    elif flow_data['IS_IPV6'] and flow_data['PROTOCOL'] == 'UDP':
                        flow_data['L7_PROTO'] = 'IPV6-UDP'
                    elif flow_data['IS_IPV6'] and flow_data['PROTOCOL'] == 'TCP':
                        flow_data['L7_PROTO'] = 'IPV6-TCP'

                # Calculate derived features
                duration_seconds = flow_data['FLOW_DURATION_MILLISECONDS'] / 1000
                if duration_seconds > 0:
                    flow_data.update({
                        'SRC_TO_DST_SECOND_BYTES': flow_data['IN_BYTES'] / duration_seconds,
                        'DST_TO_SRC_SECOND_BYTES': flow_data['OUT_BYTES'] / duration_seconds,
                        'SRC_TO_DST_AVG_THROUGHPUT': flow_data['IN_BYTES'] / duration_seconds,
                        'DST_TO_SRC_AVG_THROUGHPUT': flow_data['OUT_BYTES'] / duration_seconds,
                    })

                    # Packet size distribution
                    total_bytes = flow_data['IN_BYTES'] + flow_data['OUT_BYTES']
                    total_packets = flow_data['IN_PKTS'] + flow_data['OUT_PKTS']
                    if total_packets > 0:
                        pkt_size = total_bytes / total_packets
                        flow_data.update({
                            'NUM_PKTS_UP_TO_128_BYTES': 1 if pkt_size <= 128 else 0,
                            'NUM_PKTS_128_TO_256_BYTES': 1 if 128 < pkt_size <= 256 else 0,
                            'NUM_PKTS_256_TO_512_BYTES': 1 if 256 < pkt_size <= 512 else 0,
                            'NUM_PKTS_512_TO_1024_BYTES': 1 if 512 < pkt_size <= 1024 else 0,
                            'NUM_PKTS_1024_TO_1514_BYTES': 1 if pkt_size > 1024 else 0,
                        })

                # Send data to our server
                try:
                    response = requests.post(f"{self.server_url}/packet", json=flow_data)
                    if response.status_code != 200:
                        logging.error(f"Failed to send data to server: {response.status_code}")
                except Exception as e:
                    logging.error(f"Error sending data to server: {e}")

        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON: {e}")
        except (TypeError, ValueError) as e:
            logging.error(f"Error processing numeric values: {e}")
        except Exception as e:
            logging.error(f"Error processing line: {e}")

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('eve.json'):
            try:
                with open(event.src_path, 'r') as f:
                    f.seek(self.last_position)
                    for line in f:
                        if line.strip():  # Only process non-empty lines
                            self.process_line(line.strip())
                    self.last_position = f.tell()
            except Exception as e:
                logging.error(f"Error reading file: {e}")

def monitor_suricata_log(log_path='/var/log/suricata/eve.json', server_url='http://localhost:5000'):
    event_handler = SuricataLogHandler(server_url)
    observer = Observer()
    
    # Get the directory path from the log file path
    log_dir = os.path.dirname(log_path)
    if not log_dir:
        log_dir = '.'
        
    observer.schedule(event_handler, path=log_dir, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":    
    arg_parser = argparse.ArgumentParser(description='Monitor Suricata eve.json and forward data to IDS server')
    arg_parser.add_argument('--log-path', default='/var/log/suricata/eve.json', help='Path to Suricata eve.json')
    arg_parser.add_argument('--server-url', default='http://localhost:5000', help='URL of the IDS server')
    args = arg_parser.parse_args()

    if not os.path.exists(args.log_path):
        logging.error(f"Log file not found: {args.log_path}")
        sys.exit(1)

    monitor_suricata_log(args.log_path, args.server_url) 