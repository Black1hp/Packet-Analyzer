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
import concurrent.futures
import time

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
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
    def __init__(self, num_workers=4):
        self.packet_queue = Queue()
        self.packet_buffer = []
        self.continue_processing = True
        self.workers = []
        self.processing_lock = threading.Lock()
        
        # Create worker pool
        for _ in range(num_workers):
            worker = threading.Thread(target=self.process_queue)
            worker.daemon = True
            worker.start()
            self.workers.append(worker)

    def process_suricata_data(self, suricata_data):
        """Process Suricata data with parallel processing."""
        try:
            # Basic validation
            if not suricata_data:
                logging.warning("Received empty suricata data")
                return
                
            # Extract basic data
            source_ip = suricata_data.get('source_ip', '0.0.0.0')
            dest_ip = suricata_data.get('dest_ip', '0.0.0.0')
            source_port = suricata_data.get('source_port', 0)
            dest_port = suricata_data.get('dest_port', 0)
            protocol = suricata_data.get('protocol', 'UNKNOWN')
            
            # Process tasks in parallel using thread pool
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                # Submit tasks
                app_protocol_future = executor.submit(detect_application_protocol, suricata_data)
                activity_future = executor.submit(detect_activity_type, suricata_data)
                port_suspicious_future = executor.submit(check_port_suspicious, source_port, dest_port)
                
                # Get results
                application_protocol = app_protocol_future.result()
                activity_type = activity_future.result()
                port_suspicious = port_suspicious_future.result()
            
            # Determine risk level
            risk_level = 'HIGH' if activity_type in ['Intrusion Attempt', 'Malware Activity'] else \
                        'MEDIUM' if activity_type in ['Data Exfiltration', 'Suspicious Connection'] else 'LOW'
            
            # Check if suspicious
            is_suspicious = port_suspicious or activity_type in ['Intrusion Attempt', 'Malware Activity', 'Data Exfiltration']
            
            # Handle suspicious activity if detected (non-blocking)
            if is_suspicious:
                threading.Thread(
                    target=handle_suspicious_activity,
                    args=(
                        activity_type,
                        f"Suspicious traffic detected from {source_ip}:{source_port} to {dest_ip}:{dest_port}",
                        source_ip,
                        dest_ip,
                        protocol,
                        dest_port
                    )
                ).start()
            
            # Create packet data
            packet = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'sourceIP': source_ip,
                'destinationIP': dest_ip,
                'sourcePort': source_port,
                'destinationPort': dest_port,
                'protocol': protocol,
                'application_protocol': application_protocol,
                'activity': activity_type,
                'isSuspicious': is_suspicious,
                'size': suricata_data.get('size', 0),
                'features': {
                    'packet_rate': suricata_data.get('packet_rate', 0),
                    'byte_rate': suricata_data.get('byte_rate', 0)
                },
                'risk_level': risk_level
            }
            
            # Emit to clients directly without going through the queue again
            socketio.emit('new_packet', packet)
            
            # Add to buffer with thread safety
            with self.processing_lock:
                self.packet_buffer.append(packet)
                if len(self.packet_buffer) > 1000:
                    self.packet_buffer.pop(0)


        except Exception as e:
            logging.error(f"Error processing Suricata data: {str(e)}")
    def add_suricata_data(self, data):
        # Add data directly to the queue for processing
        if data:
            self.packet_queue.put(data)

    def process_queue(self):
        """Process packets from the queue with optimized handling."""
        while self.continue_processing:
            try:
                # Get multiple items at once if available
                items = []
                while True:
                    try:
                        item = self.packet_queue.get_nowait()
                        items.append(item)
                    except Empty:
                        break

                if items:
                    # Process items in parallel
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        executor.map(self.finalize_packet_processing, items)

                # Small sleep to prevent CPU thrashing
                time.sleep(0.01)

            except Exception as e:
                logging.error(f"Error in queue processing: {str(e)}")

    def finalize_packet_processing(self, packet_data):
        """Finalize packet processing with optimized operations."""
        try:
            with self.processing_lock:
                # Check if this is raw data or processed data
                if isinstance(packet_data, dict) and 'data' in packet_data:
                    # This is processed data from our parallel processing
                    packet = {
                        'id': str(uuid.uuid4()),
                        'timestamp': datetime.now().isoformat(),
                        'sourceIP': packet_data['data'].get('source_ip'),
                        'destinationIP': packet_data['data'].get('dest_ip'),
                        'sourcePort': packet_data['data'].get('source_port'),
                        'destinationPort': packet_data['data'].get('dest_port'),
                        'protocol': packet_data.get('protocol', 'Unknown'),
                        'activity': packet_data.get('activity', 'General Traffic'),
                        'isSuspicious': packet_data.get('port_suspicious', False),
                        'size': packet_data['data'].get('size', 0)
                    }
                else:
                    # This is raw data directly from add_suricata_data
                    # Process it directly
                    # Map Suricata field names to our expected field names
                    source_ip = packet_data.get('IPV4_SRC_ADDR', packet_data.get('source_ip', '0.0.0.0'))
                    dest_ip = packet_data.get('IPV4_DST_ADDR', packet_data.get('dest_ip', '0.0.0.0'))
                    source_port = packet_data.get('L4_SRC_PORT', packet_data.get('source_port', 0))
                    dest_port = packet_data.get('L4_DST_PORT', packet_data.get('dest_port', 0))
                    protocol_raw = packet_data.get('PROTOCOL', packet_data.get('protocol', 'TCP'))
                    app_protocol = packet_data.get('L7_PROTO', 'UNKNOWN')
                    
                    # Calculate size
                    in_bytes = int(packet_data.get('IN_BYTES', 0))
                    out_bytes = int(packet_data.get('OUT_BYTES', 0))
                    total_size = in_bytes + out_bytes
                    
                    # Calculate packet rate
                    in_pkts = int(packet_data.get('IN_PKTS', 0))
                    out_pkts = int(packet_data.get('OUT_PKTS', 0))
                    total_pkts = in_pkts + out_pkts
                    duration_ms = float(packet_data.get('FLOW_DURATION_MILLISECONDS', 0))
                    packet_rate = 0
                    if duration_ms > 0:
                        packet_rate = (total_pkts / (duration_ms / 1000))
                    
                    # Determine activity type based on protocol and ports
                    activity = 'General Traffic'
                    if app_protocol == 'DNS' or source_port == 53 or dest_port == 53:
                        activity = 'DNS Query'
                    elif app_protocol == 'HTTP' or dest_port == 80:
                        activity = 'Web Browsing'
                    elif app_protocol == 'HTTPS' or dest_port == 443:
                        activity = 'Secure Web'
                    elif app_protocol == 'SSH' or dest_port == 22:
                        activity = 'Remote Access'
                    elif app_protocol == 'SMTP' or dest_port == 25:
                        activity = 'Email'
                    elif app_protocol == 'FTP' or dest_port == 21:
                        activity = 'File Transfer'
                    elif total_size > 100000:
                        activity = 'File Transfer'
                    elif packet_rate > 50:
                        activity = 'Streaming'
                    
                    # Determine risk level
                    risk_level = 'LOW'
                    is_suspicious = False
                    if dest_port in [22, 23, 3389] or source_port in [22, 23, 3389]:
                        risk_level = 'MEDIUM'
                        is_suspicious = True
                    
                    # Basic protocol detection
                    protocol = protocol_raw
                    if app_protocol != 'UNKNOWN':
                        protocol = app_protocol
                    
                    packet = {
                        'id': str(uuid.uuid4()),
                        'timestamp': datetime.now().isoformat(),
                        'sourceIP': source_ip,
                        'destinationIP': dest_ip,
                        'sourcePort': source_port,
                        'destinationPort': dest_port,
                        'protocol': protocol,
                        'activity': activity,
                        'isSuspicious': is_suspicious,
                        'risk_level': risk_level,
                        'size': total_size,
                        'features': {
                            'packet_rate': packet_rate,
                            'byte_rate': total_size / (duration_ms / 1000) if duration_ms > 0 else 0
                        }
                    }

                # Emit to clients
                socketio.emit('new_packet', packet)
                
                # Add to buffer with size limit
                self.packet_buffer.append(packet)
                if len(self.packet_buffer) > 1000:
                    self.packet_buffer.pop(0)

        except Exception as e:
            logging.error(f"Error in final packet processing: {str(e)}")

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

def start_server(port=5000):
    try:
        # Create a global instance of SuricataHandler with optimized settings
        global suricata_handler
        suricata_handler = SuricataHandler(num_workers=4)  # Use 4 worker threads
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('packet_analyzer.log')
            ]
        )
        
        # Start the Flask server with CORS properly configured
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=port, 
            debug=True,
            allow_unsafe_werkzeug=True
        )
    except Exception as e:
        logging.error(f"Error starting server: {str(e)}")

if __name__ == "__main__":
    try:
        start_server(5000)
    except Exception as e:
        logging.error(f"Failed to start server: {e}")
        sys.exit(1)