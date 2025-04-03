from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, DNS, Raw
import keyboard
import logging
import threading
from datetime import datetime, timedelta
import json
from flask import Flask, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
import uuid
import os
import smtplib
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
import sys
from queue import Queue

load_dotenv()

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Email configuration
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ALERT_COOLDOWN_MINUTES = int(os.getenv('ALERT_COOLDOWN_MINUTES', 5))

# Blocked items storage
blocked_ips = []
blocked_ports = []

class AlertTracker:
    def __init__(self):
        self.alerts = {}  # Format: {'alert_type_key': {'last_sent': timestamp, 'details': str}}
        
    def should_send_alert(self, alert_type_key):
        if alert_type_key not in self.alerts:
            return True
        last_sent = self.alerts[alert_type_key]['last_sent']
        time_diff = datetime.now() - last_sent
        return time_diff.total_seconds() >= (ALERT_COOLDOWN_MINUTES * 60)
        
    def update_alert_timestamp(self, alert_type_key, details):
        self.alerts[alert_type_key] = {
            'last_sent': datetime.now(),
            'details': details
        }

def send_email_alert(subject, body_data):
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = SENDER_EMAIL
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = f"🚨 NIDS Alert: {subject}"

        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333333; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 20px; border-radius: 5px; border: 1px solid #ddd; }}
                .header {{ background-color: #dc3545; color: white; padding: 15px; border-radius: 5px 5px 0 0; margin: -20px -20px 20px -20px; text-align: center; }}
                .warning-icon {{ font-size: 48px; margin-bottom: 10px; }}
                .details {{ background-color: white; padding: 15px; border-radius: 5px; margin-top: 20px; border: 1px solid #ddd; }}
                .info-item {{ margin-bottom: 10px; }}
                .label {{ font-weight: bold; color: #666; }}
                .value {{ color: #333; }}
                .value.danger {{ color: #dc3545; font-weight: bold; }}
                .footer {{ margin-top: 20px; text-align: center; font-size: 12px; color: #666; }}
                .timestamp {{ text-align: right; color: #666; font-size: 12px; margin-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="warning-icon">⚠️</div>
                    <h2>Security Alert Detected</h2>
                </div>
                <div class="info-item">
                    <span class="label">Alert Type:</span>
                    <span class="value danger">{body_data['type']}</span>
                </div>
                <div class="info-item">
                    <span class="label">Description:</span>
                    <span class="value">{body_data['details']}</span>
                </div>
                <div class="details">
                    <h3>🔍 Additional Information:</h3>
                    <div class="info-item">
                        <span class="label">Source IP:</span>
                        <span class="value">{body_data['source_ip'] if body_data['source_ip'] else 'N/A'}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Destination IP:</span>
                        <span class="value">{body_data['dest_ip'] if body_data['dest_ip'] else 'N/A'}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Protocol:</span>
                        <span class="value">{body_data['protocol'] if body_data['protocol'] else 'N/A'}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Port:</span>
                        <span class="value">{body_data['port'] if body_data['port'] else 'N/A'}</span>
                    </div>
                </div>
                <div class="timestamp">
                    Detected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
                <div class="footer">
                    <p>This is an automated alert from your Network Intrusion Detection System (NIDS).<br>
                    Please take appropriate action if this activity is unauthorized.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text = f"""
NIDS Security Alert: {subject}
Alert Type: {body_data['type']}
Description: {body_data['details']}
Additional Information:
- Source IP: {body_data['source_ip'] if body_data['source_ip'] else 'N/A'}
- Destination IP: {body_data['dest_ip'] if body_data['dest_ip'] else 'N/A'}
- Protocol: {body_data['protocol'] if body_data['protocol'] else 'N/A'}
- Port: {body_data['port'] if body_data['port'] else 'N/A'}
Detected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
This is an automated alert from your Network Intrusion Detection System (NIDS).
Please take appropriate action if this activity is unauthorized.
        """

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        logging.info(f"Alert email sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def handle_suspicious_activity(activity_type, details, source_ip=None, dest_ip=None, protocol=None, port=None):
    alert_components = []
    if source_ip:
        alert_components.append(f"src:{source_ip}")
    if dest_ip:
        alert_components.append(f"dst:{dest_ip}")
    if protocol:
        alert_components.append(f"proto:{protocol}")
    if port:
        alert_components.append(f"port:{port}")
    
    alert_key = f"{activity_type}_{'.'.join(alert_components)}"
    
    if alert_tracker.should_send_alert(alert_key):
        subject = f"{activity_type}"
        body_data = {
            'type': activity_type,
            'details': details,
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'protocol': protocol,
            'port': port
        }
        send_email_alert(subject, body_data)
        alert_tracker.update_alert_timestamp(alert_key, details)

alert_tracker = AlertTracker()

def check_port_suspicious(source_port, dest_port):
    is_suspicious = any(
        (blocked_port['port'] == source_port and blocked_port['type'] == 'source') or
        (blocked_port['port'] == dest_port and blocked_port['type'] == 'destination')
        for blocked_port in blocked_ports
    )
    
    if is_suspicious:
        handle_suspicious_activity(
            "Blocked Port Activity",
            f"Connection attempt using blocked port(s): source={source_port}, dest={dest_port}",
            port=f"{source_port}->{dest_port}"
        )
    
    return is_suspicious

def detect_application_protocol(packet, sport, dport):
    common_ports = {
        22: 'SSH', 
        21: 'FTP', 
        25: 'SMTP', 
        80: 'HTTP', 
        443: 'HTTPS',
        53: 'DNS', 
        110: 'POP3', 
        143: 'IMAP', 
        3306: 'MySQL', 
        5432: 'PostgreSQL',
        3389: 'RDP',
        1433: 'MSSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT',
        8888: 'HTTP-ALT',
        9000: 'Jenkins',
        9200: 'Elasticsearch',
        9300: 'Elasticsearch-Cluster'
    }
    
    # VoIP and messaging ports
    voip_ports = {
        5060: 'SIP',
        5061: 'SIPS',
        3478: 'STUN',
        3479: 'STUN',
        3480: 'STUN',
        3481: 'STUN',
        16384: 'RTP',
        16385: 'RTP',
        16386: 'RTP',
        16387: 'RTP'
    }
    
    # Gaming ports
    gaming_ports = {
        25565: 'Minecraft',
        27015: 'Steam',
        27016: 'Steam',
        27017: 'Steam',
        27018: 'Steam',
        27019: 'Steam',
        27020: 'Steam'
    }
    
    # Check for common application ports
    if sport in common_ports:
        return common_ports[sport]
    if dport in common_ports:
        return common_ports[dport]
        
    # Check for VoIP ports
    if sport in voip_ports or dport in voip_ports:
        return 'VoIP'
        
    # Check for gaming ports
    if sport in gaming_ports or dport in gaming_ports:
        return 'Gaming'
        
    # Analyze payload for HTTP/HTTPS
    if Raw in packet:
        payload = str(packet[Raw].load)
        if any(method in payload for method in ['GET ', 'POST ', 'HTTP/']):
            return 'HTTP'
        if any(method in payload for method in ['WebSocket', 'ws://', 'wss://']):
            return 'WebSocket'
        if any(method in payload for method in ['RTSP', 'RTP']):
            return 'Streaming'
    
    if TCP in packet:
        return 'TCP'
    elif UDP in packet:
        return 'UDP'
    elif ICMP in packet:
        return 'ICMP'
    
    return 'UNKNOWN'

def detect_packet_activity(packet, packet_data):
    sport = packet_data['sourcePort']
    dport = packet_data['destinationPort']
    payload = packet_data['payload']
    size = packet_data['size']
    protocol = packet_data['protocol']

    # VoIP Detection
    if protocol == 'UDP' and 100 < size < 300:
        if sport in [16384, 16385, 16386, 16387] or dport in [16384, 16385, 16386, 16387]:
            return 'VoIP Call'
        if sport in [5060, 5061] or dport in [5060, 5061]:
            return 'VoIP Signaling'
    
    # Messaging Detection
    if protocol == 'TCP' and (sport == 443 or dport == 443) and size < 500:
        if payload and any(keyword in payload for keyword in ['POST', 'GET', 'chat', 'message', 'status']):
            return 'Messaging'
    
    # File Transfer Detection
    if protocol == 'TCP' and (sport == 80 or dport == 80 or sport == 443 or dport == 443):
        if size > 1000 or (payload and any(keyword in payload for keyword in ['Content-Disposition', 'download', 'upload'])):
            return 'File Transfer'
    
    # DNS Activity
    if protocol == 'UDP' and (sport == 53 or dport == 53):
        return 'DNS Query'
    
    # Streaming Detection
    if protocol == 'TCP' and size > 1000:
        if payload and any(keyword in payload for keyword in ['video', 'stream', 'm3u8', 'ts']):
            return 'Video Streaming'
        if payload and any(keyword in payload for keyword in ['audio', 'mp3', 'wav', 'ogg']):
            return 'Audio Streaming'
    
    # Gaming Detection
    if protocol == 'UDP' and (sport in [27015, 27016, 27017, 27018, 27019, 27020] or 
                             dport in [27015, 27016, 27017, 27018, 27019, 27020]):
        return 'Gaming'
    
    # Database Activity
    if protocol == 'TCP' and (sport in [3306, 5432, 27017, 6379] or 
                             dport in [3306, 5432, 27017, 6379]):
        return 'Database Activity'
    
    # Remote Access
    if protocol == 'TCP' and (sport == 3389 or dport == 3389):
        return 'Remote Desktop'
    
    return detect_application_protocol(packet, sport, dport)

def detect_flow_activity(flow):
    if not flow:
        return 'UNKNOWN'
    duration = (datetime.fromisoformat(flow['last_seen']) - 
                datetime.fromisoformat(flow['start_time'])).total_seconds()
    pkt_rate = flow['packet_count'] / max(duration, 1)
    avg_size = flow['total_bytes'] / flow['packet_count']

    # VoIP Call Pattern
    if avg_size < 300 and pkt_rate > 5:
        return 'VoIP Call'
    
    # File Transfer Pattern
    if avg_size > 1000 and duration > 5:
        return 'File Transfer'
    
    # Streaming Pattern
    if avg_size > 500 and pkt_rate > 2 and duration > 10:
        return 'Streaming'
    
    # Gaming Pattern
    if avg_size < 200 and pkt_rate > 10:
        return 'Gaming'
    
    # Database Pattern
    if avg_size > 500 and pkt_rate < 2:
        return 'Database Activity'
    
    return 'Messaging'

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.packet_queue = Queue()
        self.packet_buffer = []
        self.flows = {}  # Key: (src_ip, dst_ip, src_port, dst_port, proto)
        self.continue_capture = True
        self.processor_thread = threading.Thread(target=self.process_queue)
        self.processor_thread.daemon = True
        self.processor_thread.start()

    def update_flow(self, packet_data):
        flow_key = (
            packet_data['sourceIP'], packet_data['destinationIP'],
            packet_data['sourcePort'], packet_data['destinationPort'],
            packet_data['protocol']
        )
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                'start_time': packet_data['timestamp'],
                'packet_count': 0,
                'total_bytes': 0,
                'last_seen': packet_data['timestamp']
            }
        flow = self.flows[flow_key]
        flow['packet_count'] += 1
        flow['total_bytes'] += packet_data['size']
        flow['last_seen'] = packet_data['timestamp']

    def process_packet(self, packet):
        if self.packet_count % 5 != 0:  # Sample every 5th packet
            self.packet_count += 1
            return
        self.packet_count += 1
        
        packet_data = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.fromtimestamp(packet.time).isoformat(),
            'sourcePort': None,
            'destinationPort': None,
            'sourceIP': None,
            'destinationIP': None,
            'protocol': None,
            'size': len(packet),
            'isSuspicious': False,
            'payload': None,
            'activity': 'UNKNOWN',
            'flow_stats': None,
            'application_protocol': None,
            'packet_type': None,
            'risk_level': 'LOW',
            'features': {
                'duration': 0,
                'packet_rate': 0,
                'avg_size': 0,
                'is_encrypted': False,
                'is_compressed': False
            }
        }

        if IP in packet:
            packet_data['sourceIP'] = packet[IP].src
            packet_data['destinationIP'] = packet[IP].dst

        if TCP in packet:
            packet_data['sourcePort'] = packet[TCP].sport
            packet_data['destinationPort'] = packet[TCP].dport
            packet_data['protocol'] = 'TCP'
            packet_data['features']['is_encrypted'] = packet_data['sourcePort'] == 443 or packet_data['destinationPort'] == 443
        elif UDP in packet:
            packet_data['sourcePort'] = packet[UDP].sport
            packet_data['destinationPort'] = packet[UDP].dport
            packet_data['protocol'] = 'UDP'
        elif ICMP in packet:
            packet_data['protocol'] = 'ICMP'

        if Raw in packet:
            packet_data['payload'] = str(packet[Raw].load)[:100]
            # Check for compression
            if any(compression in packet_data['payload'].lower() for compression in ['gzip', 'deflate', 'compress']):
                packet_data['features']['is_compressed'] = True

        # Detect application protocol and activity
        packet_data['application_protocol'] = detect_application_protocol(packet, packet_data['sourcePort'], packet_data['destinationPort'])
        packet_data['activity'] = detect_packet_activity(packet, packet_data)
        
        # Update flow statistics
        self.update_flow(packet_data)
        flow = self.flows.get((
            packet_data['sourceIP'], packet_data['destinationIP'],
            packet_data['sourcePort'], packet_data['destinationPort'],
            packet_data['protocol']
        ))
        
        if flow:
            packet_data['flow_stats'] = flow
            packet_data['activity'] = detect_flow_activity(flow)
            # Update features
            duration = (datetime.fromisoformat(flow['last_seen']) - 
                       datetime.fromisoformat(flow['start_time'])).total_seconds()
            packet_data['features']['duration'] = duration
            packet_data['features']['packet_rate'] = flow['packet_count'] / max(duration, 1)
            packet_data['features']['avg_size'] = flow['total_bytes'] / flow['packet_count']
            
            # Determine risk level based on activity and features
            if packet_data['activity'] in ['Remote Desktop', 'Database Activity']:
                packet_data['risk_level'] = 'HIGH'
            elif packet_data['activity'] in ['File Transfer', 'VoIP Call']:
                packet_data['risk_level'] = 'MEDIUM'
            else:
                packet_data['risk_level'] = 'LOW'

        if packet_data['sourcePort'] and packet_data['destinationPort']:
            if check_port_suspicious(packet_data['sourcePort'], packet_data['destinationPort']):
                packet_data['isSuspicious'] = True
                packet_data['risk_level'] = 'HIGH'

        self.packet_buffer.append(packet_data)
        if len(self.packet_buffer) >= 10:  # Batch emit every 10 packets
            socketio.emit('packet_batch', self.packet_buffer)
            self.packet_buffer = []

    def capture_packets(self):
        logging.info("Starting packet capture...")
        sniff(filter="tcp or udp", prn=lambda pkt: self.packet_queue.put(pkt), store=0)

    def process_queue(self):
        while True:
            packet = self.packet_queue.get()
            self.process_packet(packet)
            self.packet_queue.task_done()

    def stop_capture(self):
        self.continue_capture = False
        logging.info("Packet capture stopped.")

@app.route('/health')
def health_check():
    return {'status': 'healthy'}

@socketio.on('getBlockedIPs')
def handle_get_blocked_ips():
    socketio.emit('blockedIPs', blocked_ips)

@socketio.on('getBlockedPorts')
def handle_get_blocked_ports():
    socketio.emit('blockedPorts', blocked_ports)

@socketio.on('addBlockedIP')
def handle_add_blocked_ip(ip):
    blocked_ips.append({
        'ip': ip,
        'timestamp': datetime.now().isoformat()
    })
    socketio.emit('blockedIPs', blocked_ips)

@socketio.on('removeBlockedIP')
def handle_remove_blocked_ip(ip):
    global blocked_ips
    blocked_ips = [item for item in blocked_ips if item['ip'] != ip]
    socketio.emit('blockedIPs', blocked_ips)

@socketio.on('addBlockedPort')
def handle_add_blocked_port(data):
    blocked_ports.append({
        'port': data['port'],
        'type': data['type'],
        'timestamp': datetime.now().isoformat()
    })
    socketio.emit('blockedPorts', blocked_ports)

@socketio.on('removeBlockedPort')
def handle_remove_blocked_port(data):
    global blocked_ports
    blocked_ports = [
        item for item in blocked_ports 
        if not (item['port'] == data['port'] and item['type'] == data['type'])
    ]
    socketio.emit('blockedPorts', blocked_ports)

SERVER_PORT = 5000
MAX_PORT_ATTEMPTS = 5

def find_available_port(start_port, max_attempts):
    for port in range(start_port, start_port + max_attempts):
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.bind(('0.0.0.0', port))
            test_socket.close()
            return port
        except OSError:
            continue
    return None

if __name__ == "__main__":
    sniffer = PacketSniffer()
    capture_thread = threading.Thread(target=sniffer.capture_packets)
    capture_thread.daemon = True
    capture_thread.start()

    port = find_available_port(SERVER_PORT, MAX_PORT_ATTEMPTS)
    if port is None:
        logging.error(f"Could not find an available port in range {SERVER_PORT}-{SERVER_PORT + MAX_PORT_ATTEMPTS - 1}")
        sys.exit(1)
    
    try:
        socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)
    except Exception as e:
        logging.error(f"Failed to start server: {e}")
        sys.exit(1)