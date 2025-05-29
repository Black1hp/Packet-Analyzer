#!/usr/bin/env python3
"""
ICMP Flood Detector Server Integration Module

This module integrates the ICMP Flood Detector with the Network Forensics server,
allowing it to process Suricata events and send alerts through the server's
centralized alerting system.
"""

import os
import sys
import json
import logging
from datetime import datetime
from .icmp_flood_detector_final import ICMPFloodDetector

# Configure logger
logger = logging.getLogger(__name__)

# Create a global instance of the ICMP Flood Detector
# Default threshold can be adjusted as needed
icmp_detector = ICMPFloodDetector(
    threshold=10,  # packets per second
    window_size=5,  # seconds
    alert_cooldown=60,  # seconds
    verbose=False
)

def send_icmp_flood_email_alert(source_ip, dest_ip, packet_rate, bytes_rate, packet_count=None, time_window=None, alert_type="High Rate"):
    """
    Send an email alert for ICMP flood detection with enhanced details
    """
    from backend.server import send_email_alert
    
    # Prepare alert details
    subject = f"ICMP Flood Attack Detected from {source_ip}"
    
    # Format rates with proper units
    packet_rate_formatted = f"{packet_rate:.2f}" if isinstance(packet_rate, float) else packet_rate
    bytes_rate_formatted = f"{bytes_rate:.2f}" if isinstance(bytes_rate, float) else bytes_rate
    
    # Convert bytes rate to more readable format if it's a number
    if isinstance(bytes_rate, (int, float)) and bytes_rate > 1024*1024:
        bytes_rate_readable = f"{bytes_rate/1024/1024:.2f} MB/s"
    elif isinstance(bytes_rate, (int, float)) and bytes_rate > 1024:
        bytes_rate_readable = f"{bytes_rate/1024:.2f} KB/s"
    else:
        bytes_rate_readable = f"{bytes_rate_formatted} bytes/s"
        
    # Prepare body with detailed information
    body_data = {
        "type": "ICMP Flood",
        "details": f"ICMP flood attack ({alert_type}) detected from {source_ip} to {dest_ip}",
        "source_ip": source_ip,
        "sourceIP": source_ip,  # Alternative field name for consistency
        "destination_ip": dest_ip,
        "destinationIP": dest_ip,  # Alternative field name for consistency
        "packets_per_second": packet_rate_formatted,
        "bytes_per_second": bytes_rate_readable,
        "raw_bytes_per_second": bytes_rate,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "alert_level": alert_type,
        "protocol": "ICMP"
    }
    
    # Add optional fields if provided
    if packet_count is not None:
        body_data["packet_count"] = packet_count
    
    if time_window is not None:
        if isinstance(time_window, (int, float)):
            body_data["time_window"] = f"{time_window:.2f} seconds"
        else:
            body_data["time_window"] = time_window
    
    # Send the alert
    try:
        send_email_alert(subject, body_data, alert_type_for_email_subject="ICMP Flood")
        return True
    except Exception as e:
        logger.error(f"Error sending ICMP flood email alert: {e}")
        return False

def process_suricata_event(event_data):
    """
    Process a Suricata event to detect ICMP flood attacks.
    This function is called by the server.py module.
    
    Args:
        event_data (dict): Suricata event data
        
    Returns:
        dict: Detection result if attack detected, None otherwise
    """
    try:
        # Skip non-ICMP events
        if event_data.get('proto') != 'ICMP':
            return None
            
        # Convert event_data to JSON string for the detector
        event_json_str = json.dumps(event_data)
        
        # Process the event using the ICMP Flood Detector
        result = icmp_detector.process_suricata_eve(event_json_str)
        
        # If attack detected, format the result for the server
        if result and result[0]:
            is_attack, alert_data = result
            
            # Create detection result
            detection_result = {
                'type': 'icmp_flood',
                'timestamp': datetime.now().isoformat(),
                'src_ip': alert_data['src_ip'],
                'dst_ip': alert_data['dst_ip'],
                'packets_per_second': alert_data['packets_per_second'],
                'bytes_per_second': alert_data['bytes_per_second'],
                'packet_count': alert_data['packet_count'],
                'time_window': alert_data.get('time_window', 0)
            }
            
            logger.info(f"[+] Detected ICMP Flood attack from {alert_data['src_ip']} to {alert_data['dst_ip']}")
            logger.info(f"    Packets/sec: {alert_data['packets_per_second']:.2f}")
            logger.info(f"    Bytes/sec: {alert_data['bytes_per_second']:.2f}")
            
            # Send email alert with detailed information
            send_icmp_flood_email_alert(alert_data['src_ip'], alert_data['dst_ip'], alert_data['packets_per_second'], alert_data['bytes_per_second'], packet_count=alert_data['packet_count'], time_window=alert_data.get('time_window', 0))
            
            return detection_result
            
    except Exception as e:
        logger.error(f"Error in process_suricata_event: {e}")
    
    return None
