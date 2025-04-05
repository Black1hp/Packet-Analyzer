import json
from datetime import datetime

# Path to eve.json
EVE_JSON_PATH = '/var/log/suricata/eve.json'

# Function to calculate duration in milliseconds
def calculate_duration(start, end):
    start_time = datetime.fromisoformat(start.replace('Z', '+00:00'))
    end_time = datetime.fromisoformat(end.replace('Z', '+00:00'))
    duration = (end_time - start_time).total_seconds() * 1000
    return duration if duration > 0 else 1  # Avoid division by zero

# Function to check if an IP is IPv4
def is_ipv4(ip):
    return '.' in ip and ':' not in ip

# Function to process eve.json and extract all dataset fields
def process_eve_json():
    flow_data = {}  # Store flow data by flow_id
    tcp_data = {}   # Store TCP data by flow_id

    with open(EVE_JSON_PATH, 'r') as f:
        for line in f:
            event = json.loads(line)
            event_type = event.get('event_type')
            flow_id = event.get('flow_id')

            # Process flow events (IPv4 only)
            if event_type == 'flow' and 'src_port' in event and is_ipv4(event['src_ip']) and is_ipv4(event['dest_ip']):
                duration = calculate_duration(event['flow']['start'], event['flow']['end'])
                flow_data[flow_id] = {
                    'IPV4_SRC_ADDR': event['src_ip'],
                    'L4_SRC_PORT': event['src_port'],
                    'IPV4_DST_ADDR': event['dest_ip'],
                    'L4_DST_PORT': event['dest_port'],
                    'PROTOCOL': event['proto'],
                    'L7_PROTO': event.get('app_proto', 'UNKNOWN'),
                    'IN_BYTES': event['flow']['bytes_toserver'],
                    'IN_PKTS': event['flow']['pkts_toserver'],
                    'OUT_BYTES': event['flow']['bytes_toclient'],
                    'OUT_PKTS': event['flow']['pkts_toclient'],
                    'FLOW_DURATION_MILLISECONDS': duration,
                    'SRC_TO_DST_SECOND_BYTES': event['flow']['bytes_toserver'] / (duration / 1000),
                    'DST_TO_SRC_SECOND_BYTES': event['flow']['bytes_toclient'] / (duration / 1000),
                    'SRC_TO_DST_AVG_THROUGHPUT': event['flow']['bytes_toserver'] / (duration / 1000),
                    'DST_TO_SRC_AVG_THROUGHPUT': event['flow']['bytes_toclient'] / (duration / 1000),
                    # Approximate packet size bins (assuming average packet size)
                    'NUM_PKTS_UP_TO_128_BYTES': 0,  # Placeholder
                    'NUM_PKTS_128_TO_256_BYTES': 0,  # Placeholder
                    'NUM_PKTS_256_TO_512_BYTES': event['flow']['pkts_toserver'] + event['flow']['pkts_toclient'],  # Rough guess for DHCP
                    'NUM_PKTS_512_TO_1024_BYTES': 0,  # Placeholder
                    'NUM_PKTS_1024_TO_1514_BYTES': 0,  # Placeholder
                    'ICMP_TYPE': None,
                    'ICMP_IPV4_TYPE': None,
                    'DNS_QUERY_ID': None,
                    'DNS_QUERY_TYPE': None,
                    'DNS_TTL_ANSWER': None,
                }

            # Process TCP events
            elif event_type == 'tcp' and flow_id:
                if flow_id not in tcp_data:
                    tcp_data[flow_id] = {'CLIENT_FLAGS': [], 'SERVER_FLAGS': [], 'TCP_WIN_MAX_IN': 0, 'TCP_WIN_MAX_OUT': 0}
                # Assume 'toserver' is client, 'toclient' is server (heuristic)
                tcp_flags = event['tcp'].get('tcp_flags', '00')
                if 'flow' in event and event['flow']['pkts_toserver'] > 0:
                    tcp_data[flow_id]['CLIENT_FLAGS'].append(tcp_flags)
                if 'flow' in event and event['flow']['pkts_toclient'] > 0:
                    tcp_data[flow_id]['SERVER_FLAGS'].append(tcp_flags)
                tcp_win = event['tcp'].get('window', 0)
                if 'flow' in event and event['flow']['pkts_toserver'] > 0 and tcp_win > tcp_data[flow_id]['TCP_WIN_MAX_IN']:
                    tcp_data[flow_id]['TCP_WIN_MAX_IN'] = tcp_win
                if 'flow' in event and event['flow']['pkts_toclient'] > 0 and tcp_win > tcp_data[flow_id]['TCP_WIN_MAX_OUT']:
                    tcp_data[flow_id]['TCP_WIN_MAX_OUT'] = tcp_win

            # Process DNS events
            elif event_type == 'dns' and flow_id in flow_data:
                flow_data[flow_id]['DNS_QUERY_ID'] = event['dns'].get('id', 0)
                flow_data[flow_id]['DNS_QUERY_TYPE'] = event['dns'].get('rrtype', 'N/A')
                flow_data[flow_id]['DNS_TTL_ANSWER'] = event['dns'].get('ttl', None)

            # Process ICMP events
            elif event_type == 'icmp' or (event_type == 'flow' and 'icmp_type' in event):
                if flow_id in flow_data:
                    flow_data[flow_id]['ICMP_TYPE'] = event.get('icmp_type', 0)
                    flow_data[flow_id]['ICMP_IPV4_TYPE'] = event.get('icmp_type', 0)

    # Combine and print flow data with TCP info
    for flow_id, data in flow_data.items():
        if flow_id in tcp_data:
            data['TCP_FLAGS'] = ','.join(set(tcp_data[flow_id]['CLIENT_FLAGS'] + tcp_data[flow_id]['SERVER_FLAGS']))
            data['CLIENT_TCP_FLAGS'] = ','.join(set(tcp_data[flow_id]['CLIENT_FLAGS'])) if tcp_data[flow_id]['CLIENT_FLAGS'] else 'N/A'
            data['SERVER_TCP_FLAGS'] = ','.join(set(tcp_data[flow_id]['SERVER_FLAGS'])) if tcp_data[flow_id]['SERVER_FLAGS'] else 'N/A'
            data['TCP_WIN_MAX_IN'] = tcp_data[flow_id]['TCP_WIN_MAX_IN']
            data['TCP_WIN_MAX_OUT'] = tcp_data[flow_id]['TCP_WIN_MAX_OUT']
        else:
            data['TCP_FLAGS'] = 'N/A'
            data['CLIENT_TCP_FLAGS'] = 'N/A'
            data['SERVER_TCP_FLAGS'] = 'N/A'
            data['TCP_WIN_MAX_IN'] = 0
            data['TCP_WIN_MAX_OUT'] = 0
        print(json.dumps(data))

if __name__ == "__main__":
    process_eve_json()