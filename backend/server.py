from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS
import logging
import threading
from datetime import datetime
import json
import uuid
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
import sys
from queue import Queue, Empty

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
        self.alerts = {}
        
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

alert_tracker = AlertTracker()

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

def detect_application_protocol(suricata_data):
    l7_proto = suricata_data.get('L7_PROTO', '').upper()
    if l7_proto:
        return l7_proto
    
    protocol = suricata_data.get('PROTOCOL', '').upper()
    src_port = suricata_data.get('L4_SRC_PORT')
    dst_port = suricata_data.get('L4_DST_PORT')
    
    common_ports = {
        80: 'HTTP',
        443: 'HTTPS',
        22: 'SSH',
        53: 'DNS',
        3306: 'MySQL',
        5432: 'PostgreSQL'
    }
    
    if src_port in common_ports:
        return common_ports[src_port]
    if dst_port in common_ports:
        return common_ports[dst_port]
    
    return protocol

def detect_activity_type(suricata_data):
    protocol = suricata_data.get('PROTOCOL', '').upper()
    l7_proto = suricata_data.get('L7_PROTO', '').upper()
    src_port = suricata_data.get('L4_SRC_PORT')
    dst_port = suricata_data.get('L4_DST_PORT')
    in_bytes = suricata_data.get('IN_BYTES', 0)
    out_bytes = suricata_data.get('OUT_BYTES', 0)
    duration = suricata_data.get('FLOW_DURATION_MILLISECONDS', 0)
    
    # DNS Activity
    if l7_proto == 'DNS' or src_port == 53 or dst_port == 53:
        return 'DNS Query'
    
    # Database Activity
    if src_port in [3306, 5432, 27017, 6379] or dst_port in [3306, 5432, 27017, 6379]:
        return 'Database Activity'
    
    # VoIP Detection
    if protocol == 'UDP':
        if src_port in [5060, 5061, 16384, 16385, 16386, 16387] or \
           dst_port in [5060, 5061, 16384, 16385, 16386, 16387]:
            return 'VoIP Call'
    
    # File Transfer Detection
    total_bytes = in_bytes + out_bytes
    if total_bytes > 100000:  # More than 100KB
        return 'File Transfer'
    
    # Streaming Detection
    if duration > 1000 and (in_bytes/duration > 1000 or out_bytes/duration > 1000):
        return 'Video Streaming'
    
    return 'Messaging'

class SuricataHandler:
    def __init__(self):
        self.packet_queue = Queue()
        self.packet_buffer = []
        self.continue_processing = True
        self.processor_thread = threading.Thread(target=self.process_queue)
        self.processor_thread.daemon = True
        self.processor_thread.start()

    def process_suricata_data(self, suricata_data):
        try:
            packet_data = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'sourcePort': suricata_data.get('L4_SRC_PORT'),
                'destinationPort': suricata_data.get('L4_DST_PORT'),
                'sourceIP': suricata_data.get('IPV4_SRC_ADDR'),
                'destinationIP': suricata_data.get('IPV4_DST_ADDR'),
                'protocol': suricata_data.get('PROTOCOL', 'UNKNOWN'),
                'size': suricata_data.get('IN_BYTES', 0) + suricata_data.get('OUT_BYTES', 0),
                'isSuspicious': False,
                'activity': 'UNKNOWN',
                'application_protocol': suricata_data.get('L7_PROTO', 'UNKNOWN').upper(),
                'risk_level': 'LOW',
                'features': {
                    'duration': float(suricata_data.get('FLOW_DURATION_MILLISECONDS', 0)),
                    'packet_rate': 0,
                    'avg_size': 0,
                    'is_encrypted': suricata_data.get('L7_PROTO', '').lower() in ['https', 'ssh', 'ssl'],
                    'is_compressed': False
                }
            }

            # Calculate packet rate and average size
            total_packets = (suricata_data.get('IN_PKTS', 0) + suricata_data.get('OUT_PKTS', 0))
            if total_packets > 0 and packet_data['features']['duration'] > 0:
                packet_data['features']['packet_rate'] = total_packets / (packet_data['features']['duration'] / 1000)
                packet_data['features']['avg_size'] = packet_data['size'] / total_packets

            # Determine activity type based on protocol and features
            if packet_data['application_protocol'] == 'DNS':
                packet_data['activity'] = 'DNS Query'
            elif packet_data['protocol'] == 'UDP' and packet_data['features']['packet_rate'] > 50:
                packet_data['activity'] = 'VoIP Call'
            elif packet_data['size'] > 100000:
                packet_data['activity'] = 'File Transfer'
            elif packet_data['features']['packet_rate'] > 100:
                packet_data['activity'] = 'Video Streaming'
            else:
                packet_data['activity'] = 'Messaging'

            # Set risk level
            if packet_data['activity'] in ['Database Activity', 'Remote Desktop']:
                packet_data['risk_level'] = 'HIGH'
            elif packet_data['activity'] in ['File Transfer', 'VoIP Call']:
                packet_data['risk_level'] = 'MEDIUM'

            if packet_data['sourcePort'] and packet_data['destinationPort']:
                if check_port_suspicious(packet_data['sourcePort'], packet_data['destinationPort']):
                    packet_data['isSuspicious'] = True
                    packet_data['risk_level'] = 'HIGH'

            self.packet_buffer.append(packet_data)
            if len(self.packet_buffer) >= 10:
                socketio.emit('packet_batch', self.packet_buffer)
                self.packet_buffer = []

        except Exception as e:
            logging.error(f"Error processing Suricata data: {e}")

    def add_suricata_data(self, data):
        self.packet_queue.put(data)

    def process_queue(self):
        while self.continue_processing:
            try:
                data = self.packet_queue.get(timeout=1)
                self.process_suricata_data(data)
                self.packet_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logging.error(f"Error in process_queue: {e}")
                continue

    def stop_processing(self):
        self.continue_processing = False

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

@app.route('/packet', methods=['POST'])
def receive_packet():
    try:
        data = request.json
        if suricata_handler:
            suricata_handler.add_suricata_data(data)
        return jsonify({'status': 'success'})
    except Exception as e:
        logging.error(f"Error processing packet data: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Create a global instance of SuricataHandler
suricata_handler = None

def start_server(port=5000):
    global suricata_handler
    suricata_handler = SuricataHandler()
    socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)

if __name__ == "__main__":
    try:
        start_server(5000)
    except Exception as e:
        logging.error(f"Failed to start server: {e}")
        sys.exit(1)