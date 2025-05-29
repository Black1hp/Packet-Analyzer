# Network Intrusion Detection System

## Overview

This project is a comprehensive Network Intrusion Detection System designed to monitor network traffic, detect various types of cyber attacks, and provide real-time alerts through email notifications. The system integrates Suricata with custom detection modules and provides detailed information about detected threats.

## Key Features

- **Multi-threat Detection**: Detects multiple types of network threats:
  - **Port Scanning**: Uses machine learning to identify and classify port scanning activities with high accuracy
  - **ICMP Flood Attacks**: Advanced detection of ICMP flood attacks with traffic rate analysis
  - **Malware Detection**: Identifies potentially malicious file downloads and checks them against VirusTotal

- **Real-time Email Alerts**: Comprehensive email notifications with:  
  - Color-coded threat categorization
  - Detailed information specific to each threat type
  - Visual presentation of attack characteristics
  - Actionable security recommendations

- **Suricata Integration**: Leverages Suricata's powerful traffic inspection capabilities

- **Machine Learning**: Uses trained models to detect sophisticated attacks that signature-based systems might miss

- **Centralized Alert System**: Unified alerting system across all detection modules

## Architecture

The system consists of several integrated components:

1. **Core Server**: Flask-based backend that coordinates all detection modules
2. **Suricata Integration**: Processes network traffic and generates events
3. **Specialized Detectors**:
   - ML-based Port Scan Detector
   - ICMP Flood Detector
   - Malware Detection Module
4. **Alert System**: Email notification system with detailed threat information

## Prerequisites

- Python 3.8+ (3.9 recommended)
- Suricata 6.0+ (for production use)
- SMTP server access for email alerts
- VirusTotal API key (for malware detection functionality)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/Network-Forensics.git
   cd Network-Forensics
   ```

2. **Install dependencies**:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. **Configure environment variables**:
   Create a `.env` file in the project root with the following parameters:
   ```
   # Email Configuration
   SMTP_SERVER=smtp.example.com
   SMTP_PORT=587
   SENDER_EMAIL=your-email@example.com
   SENDER_PASSWORD=your-email-password
   ADMIN_EMAIL=admin-email@example.com
   
   # VirusTotal API
   VIRUSTOTAL_API_KEY=your-virustotal-api-key
   
   # Detection Configuration
   ML_TARGET_IP=your-protected-ip  # IP to monitor for port scans
   ML_SCAN_THRESHOLD=10            # Number of unique ports to trigger detection
   ML_TIME_INTERVAL=30             # Time window in seconds
   ML_ALERT_COOLDOWN_MINUTES=5     # Minimum time between alerts
   
   # File paths
   EVE_JSON_LOG_PATH=/var/log/suricata/eve.json  # Path to Suricata EVE log
   ML_MODEL_PATH=backend/ml_port_scan_detector/portscan_detector_model.pkl
   ML_SCALER_PATH=backend/ml_port_scan_detector/scaler.pkl
   ```

4. **Suricata Setup** (if using with Suricata):
   - Install Suricata following official documentation
   - Use the provided `suricata.yaml` configuration or modify your existing one
   - Ensure Suricata is writing to the EVE log path specified in your `.env`

## Usage

### Starting the System

1. **Start the main detection server**:
   ```bash
   python backend/server.py
   ```

2. **Testing the alerts system**:
   ```bash
   python test_all_alerts.py
   ```
   This will send test email alerts for all detection types to verify your email configuration.

### Testing Attack Detection

#### Port Scan Detection Testing

1. **Using Nmap for testing** (from Kali Linux or other machine):
   ```bash
   # Basic scan
   nmap -p 1-1000 [target_ip]
   
   # More aggressive scan (more likely to trigger detection)
   nmap -sS -T4 -p 1-65535 [target_ip]
   ```

2. **Expected results**:
   - The system should detect the scan and send an email alert
   - The alert will contain details about:
     - Source IP (attacker)
     - Target IP
     - Ports scanned
     - Critical services targeted
     - Scan type (sequential or distributed)

#### ICMP Flood Attack Testing

1. **Using ping flood** (requires root privileges):
   ```bash
   # From Linux:
   sudo ping -f [target_ip]
   
   # For more aggressive testing (hping3):
   sudo hping3 --icmp --flood [target_ip]
   ```

2. **Expected results**:
   - The system should detect the ICMP flood and send an email alert
   - The alert will contain details about:
     - Attack source
     - Target IP
     - Packet rate (packets/second)
     - Data rate (bytes/second)
     - Attack duration

#### Malware Detection Testing

1. **Using the EICAR test file**:
   - Download the [EICAR test file](https://www.eicar.org/?page_id=3950) through HTTP/HTTPS while the system is monitoring
   - Alternatively, use the built-in test:
     ```bash
     python backend/malware_detector/test_detector.py
     ```

2. **Expected results**:
   - The system should detect the potential malware and send an email alert
   - The alert will contain details about:
     - Filename
     - Download URL
     - File hash
     - VirusTotal verdict
     - Detection ratio

## Advanced Configuration

### Customizing Detection Thresholds

#### Port Scan Detection

Edit the following variables in your `.env` file:
- `ML_SCAN_THRESHOLD`: Number of unique ports to trigger detection (default: 10)
- `ML_TIME_INTERVAL`: Time window in seconds to monitor connections (default: 30)

#### ICMP Flood Detection

Modify `backend/icmp_detector/icmp_server_integration.py` to adjust:
- `threshold`: Packets per second to trigger detection (default: 10)
- `window_size`: Detection window in seconds (default: 5)
- `alert_cooldown`: Seconds between alerts (default: 60)

### Email Alert Customization

Modify `backend/server.py` to customize the email alert templates:
- HTML formatting is in the `send_email_alert` function
- Alert colors and styling can be adjusted in the same function

## Project Structure

```
Network-Forensics/
├── .env                     # Environment configuration
├── test_all_alerts.py       # Test script for email alerts
├── backend/
│   ├── server.py            # Main detection server
│   ├── requirements.txt      # Python dependencies
│   ├── malware_detector/     # Malware detection module
│   │   ├── malware_detector.py
│   │   ├── malicious_file_types.py
│   │   └── test_detector.py
│   ├── ml_port_scan_detector/ # ML-based port scan detection
│   │   ├── portscan_detector_model.pkl
│   │   └── scaler.pkl
│   └── icmp_detector/        # ICMP flood detection module
│       ├── icmp_flood_detector_final.py
│       └── icmp_server_integration.py
└── logs/                    # Log files directory
```

## Troubleshooting

### Email Alerts Not Received

1. **Check SMTP configuration**:
   - Verify SMTP server and port are correct
   - Ensure email credentials are valid
   - Some providers require "Less secure app access" to be enabled

2. **Run the test script**:
   ```bash
   python test_all_alerts.py
   ```

3. **Check logs**:
   - Look for errors in the server output
   - Check if alerts are being triggered but emails are failing

### Detection Not Working

1. **Port Scanning**:
   - Ensure ML_TARGET_IP is set to the IP you're targeting with scans
   - Verify the ML model files exist and are correctly specified
   - Try more aggressive scans to trigger detection

2. **ICMP Flood**:
   - Ensure you're sending sufficient ICMP packets to exceed threshold
   - Verify Suricata is correctly processing ICMP packets

3. **Malware Detection**:
   - Check your VirusTotal API key is valid
   - Verify the system can access VirusTotal's API
   - Test with known malicious file hashes

## Security Considerations

- This system is designed for educational and monitoring purposes
- In production environments, secure your API keys and credentials
- Consider network segmentation to protect the detection system from attacks
- Regularly update Suricata rules for optimal detection capabilities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue for any bugs or feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
