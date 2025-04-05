# 🔍 Network Traffic Analysis System with IDS

A real-time network traffic analysis system with Intrusion Detection System (IDS) capabilities, featuring a modern web interface and machine learning-based threat detection.

## ⭐ Features

- 🔄 Real-time network traffic monitoring using Suricata
- 🌐 Modern web interface with real-time updates
- 🤖 Machine learning-based traffic analysis
- 🚨 Customizable alert system
- 📊 Traffic visualization and statistics
- 🛡️ IP and Port blocking capabilities
- 📝 Protocol analysis and classification
- 🌐 DNS traffic monitoring
- 📈 Throughput and packet size analysis

## 📋 Prerequisites

- 🐍 Python 3.8 or higher
- 📦 Node.js 14.x or higher
- 🛡️ Suricata 6.0 or higher
- 💻 Linux/Unix-based system (recommended)
- 🔄 Git

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-traffic-analyzer.git
cd network-traffic-analyzer
```

2. Set up the backend:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

3. Set up the frontend:
```bash
cd ../frontend
npm install
```

4. Configure Suricata:
- Install Suricata if not already installed:
```bash
sudo apt-get update
sudo apt-get install suricata
```
- Update Suricata configuration:
```bash
sudo nano /etc/suricata/suricata.yaml
```
- Enable EVE logging and set the output path to `/var/log/suricata/eve.json`

5. Set up environment variables:
```bash
cd ../backend
cp .env.example .env
```
Edit the .env file with your configuration:
```
SMTP_SERVER=your_smtp_server
SMTP_PORT=587
SENDER_EMAIL=your_email
SENDER_PASSWORD=your_password
ADMIN_EMAIL=admin_email
ALERT_COOLDOWN_MINUTES=5
```

## 🎮 Usage

1. Start Suricata:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i <your-network-interface>
```

2. Start the backend server:
```bash
cd backend
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
python server.py
```

3. Start the Suricata integration:
```bash
python suricata_integration.py --log-path /var/log/suricata/eve.json
```

4. Start the frontend development server:
```bash
cd frontend
npm run dev
```

5. Access the web interface:
Open your browser and navigate to `http://localhost:3000`

## 🛠️ Features Usage

### 🔍 Real-time Traffic Monitoring
- 👀 View live network traffic in the main dashboard
- 🔎 Filter traffic by protocol, IP, or port
- 📝 View detailed packet information by clicking on individual entries

### 🛡️ Blocking Rules
1. IP Blocking:
   - 🚫 Navigate to the "Blocking Rules" section
   - ➕ Add IP addresses to block
   - 📋 View and manage blocked IPs

2. Port Blocking:
   - 🔒 Add source or destination ports to block
   - ⚙️ Set port blocking rules by protocol

### ⚠️ Alerts
- 🎚️ Configure alert thresholds in the settings
- 🔔 View alerts in real-time
- 📤 Export alert logs
- 📧 Receive email notifications for critical events

### 📊 Traffic Analysis
- 📈 View traffic patterns and statistics
- 🔄 Analyze protocol distribution
- 📉 Monitor network throughput
- 🌐 Track DNS queries and responses

## ❗ Troubleshooting

1. If Suricata fails to start:
   - 🔍 Check if the network interface is correct
   - 📝 Verify Suricata configuration file
   - 🔑 Check system permissions

2. If the backend server fails:
   - ✅ Verify Python virtual environment is activated
   - 📦 Check all dependencies are installed
   - 🔌 Verify port 5000 is available

3. If the frontend fails to connect:
   - 🔄 Check if backend server is running
   - 🌐 Verify WebSocket connection
   - 🔍 Check browser console for errors

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

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details. 