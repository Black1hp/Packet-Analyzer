#!/usr/bin/env python3
"""
Test script for the Network Intrusion Detection System's email alerts

This script tests all types of alerts to verify that the email functionality
is working correctly with the new enhanced email format.
"""

import os
import sys
import json
import logging
from datetime import datetime
from dotenv import load_dotenv

# Add the project root to the path to import modules correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import alert function
from backend.server import send_email_alert

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def test_port_scan_alert():
    """Test port scanning detection alert"""
    logger.info("Testing port scan alert...")
    
    # Sample data for a port scan alert
    subject = "Port Scan Detected from 192.168.1.100"
    alert_data = {
        'type': 'ML Port Scan',
        'details': "ML model detected a port scan from 192.168.1.100 targeting 192.168.1.1.\nTotal ports scanned: 45\nCritical services targeted: 22 (SSH), 80 (HTTP), 443 (HTTPS)\nScan type: Sequential port scan",
        'source_ip': '192.168.1.100',
        'dest_ip': '192.168.1.1',
        'protocol': 'TCP',
        'ports': [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080],
        'timestamp': datetime.now().isoformat(),
        'sourceIP': '192.168.1.100',
        'destinationIP': '192.168.1.1',
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Send the alert
    result = send_email_alert(subject, alert_data, alert_type_for_email_subject="Port Scan Alert")
    logger.info(f"Port scan alert sent: {result}")
    return result

def test_icmp_flood_alert():
    """Test ICMP flood detection alert"""
    logger.info("Testing ICMP flood alert...")
    
    # Sample data for an ICMP flood alert
    subject = "ICMP Flood Attack Detected from 192.168.1.200"
    alert_data = {
        'type': 'ICMP Flood',
        'details': "ICMP flood attack (High Rate) detected from 192.168.1.200 to 192.168.1.1",
        'source_ip': '192.168.1.200',
        'sourceIP': '192.168.1.200',
        'destination_ip': '192.168.1.1',
        'destinationIP': '192.168.1.1',
        'packets_per_second': '1542.5',
        'bytes_per_second': '1.25 MB/s',
        'packet_count': 7712,
        'time_window': '5.00 seconds',
        'timestamp': datetime.now().isoformat(),
        'alert_level': 'High Rate',
        'protocol': 'ICMP'
    }
    
    # Send the alert
    result = send_email_alert(subject, alert_data, alert_type_for_email_subject="ICMP Flood")
    logger.info(f"ICMP flood alert sent: {result}")
    return result

def test_malware_alert():
    """Test malware detection alert"""
    logger.info("Testing malware detection alert...")
    
    # Sample data for a malware detection alert
    subject = "Malware Detection: malicious_sample.exe"
    alert_data = {
        'type': 'malware_detection',
        'filename': 'malicious_sample.exe',
        'url': 'http://suspicious-site.com/downloads/malicious_sample.exe',
        'hash': 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
        'verdict': 'MALICIOUS',
        'detection_ratio': '32/68',
        'file_size': '1.25 MB',
        'content_type': 'application/x-msdownload',
        'timestamp': datetime.now().isoformat(),
        'details': "Potentially malicious file detected: malicious_sample.exe\nVerdict: MALICIOUS\nDetection ratio: 32/68",
        'source_ip': '192.168.1.150',
        'destination_ip': '192.168.1.10',
        'sourceIP': '192.168.1.150',
        'destinationIP': '192.168.1.10',
        'protocol': 'HTTP'
    }
    
    # Send the alert
    result = send_email_alert(subject, alert_data, alert_type_for_email_subject="Malware Detection")
    logger.info(f"Malware alert sent: {result}")
    return result

def run_all_tests():
    """Run all test alert functions"""
    results = []
    
    # Test port scan alert
    port_scan_result = test_port_scan_alert()
    results.append(("Port Scan Alert", port_scan_result))
    
    # Test ICMP flood alert
    icmp_flood_result = test_icmp_flood_alert()
    results.append(("ICMP Flood Alert", icmp_flood_result))
    
    # Test malware alert
    malware_result = test_malware_alert()
    results.append(("Malware Detection Alert", malware_result))
    
    # Print summary
    logger.info("\n--- Test Results Summary ---")
    all_success = True
    for test_name, result in results:
        status = "SUCCESS" if result else "FAILED"
        logger.info(f"{test_name}: {status}")
        if not result:
            all_success = False
    
    if all_success:
        logger.info("\nAll email alerts sent successfully!")
    else:
        logger.error("\nSome email alerts failed to send. Check the logs for details.")

if __name__ == "__main__":
    print("Network Intrusion Detection System - Email Alert Test")
    print("====================================================")
    print("This script will send test emails for all alert types.")
    print("Make sure your .env file is properly configured with email settings.")
    print("\nSending test alerts...")
    run_all_tests()
