# Network Security Monitoring System

A comprehensive network security monitoring system that combines real-time packet analysis, honeypot capabilities, and threat intelligence integration.

## 👥 Team Members
1. Mohamed Saied
2. Ahmed Eldesouki 
3. Mohamed Wael 
4. Essameldin Amr
5. Ahmed Abdelmoniem
6. Marwan HossamEldin
7. Randa Emam
8. Monira Mahmoud
9. Ahmed Tarek

## 🚀 Features

### 🔍 Network Analysis
- Real-time packet capture and analysis using Scapy
- Protocol identification (HTTP, HTTPS, DNS, SSH, etc.)
- TCP, UDP, ICMP traffic monitoring
- Packet size and volume statistics
- Timestamp tracking for traffic patterns

### 🛡️ Security Monitoring
- Port-based suspicious activity detection
- Customizable blocked IP management
- Suspicious port activity tracking
- Packet inspection for potential threats
- Real-time threat flagging system

### 📊 Visualization Dashboard
- Real-time network traffic visualization
- Web-based interactive interface
- Suspicious activity highlighting
- Protocol distribution charts
- Traffic volume metrics

### 📧 Alert System
- SMTP-based email notifications
- Customizable alert thresholds
- Critical event notifications
- Detailed attack reports
- Automated incident reporting

### 🖥️ Administration Tools
- Blocked IP management
- Port blocking configuration
- Alert threshold customization
- System health monitoring
- Email notification settings

## 📋 Prerequisites
- Python 3.8+
- Node.js and npm
- Network interface with monitor mode capability
- Administrator/root privileges (for packet capture)
- SMTP server access (for email alerts)

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/Black1hp/Packet-Analyzer.git
cd Packet-Analyzer

# Install backend dependencies
cd backend
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your SMTP settings

# Install frontend dependencies
cd ..
npm install

# Start the application
# Terminal 1 (Backend):
cd backend
python server.py

# Terminal 2 (Frontend):
npm run dev
```

## 🚀 Usage
1. Access the web interface at http://localhost:5173
2. Monitor real-time network traffic
3. Configure blocked IPs and ports
4. Set up email notifications
5. Analyze suspicious activities

## 📚 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details. 