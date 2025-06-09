# private5G_Anomalydetection
📡 Private5G_AnomalyDetection
An autonomous agent designed to monitor and analyze traffic in private 5G networks using packet capture, anomaly detection, and closed-loop diagnostics.

 Features
 Remote Packet Capture via SSH using tcpdump

 Packet Inspection using Scapy

Feature Extraction into structured CSV from .pcap

⚠Unsupervised Anomaly Detection with Isolation Forest

📁 Logs, Reports & Data Management built-in
Integrated with prometheus and grafana

🔁 Fully Agentic Loop — captures, processes, detects, waits, repeats
 Project Structure
.
├── agent.py                  # Main agent loop
├── extract_features.py       # Extract features from PCAP to CSV
├── detect_anomalies.py       # ML-based anomaly detection
├── config.ini.txt            # SSH & capture settings
├── captures/                 # PCAPs and reports
├── logs/                     # Log files
├── deep_anomaly_scan.sh      # Optional external scan hook
└── README.md
⚙️ How It Works
Connects via SSH to a 5G edge node

Runs tcpdump remotely to capture live packets

Downloads and deletes the .pcap file

Extracts packet-level features into a CSV

Applies anomaly detection using Isolation Forest

Logs and stores the output for further use

🛠️ Setup Instructions
1. Clone this repo

git clone https://github.com/yourusername/private5G_AnomalyDetection.git
cd private5G_AnomalyDetection
2. Install dependencies
bash
Copy
Edit
pip install -r requirements.txt
(example packages used)

txt
Copy
Edit
scapy
paramiko
scp
pandas
scikit-learn
3. Configure the agent
Edit config.ini.txt:

ini

[ssh_server]
hostname = 192.168.1.100
port = 22
username = your_user
password = your_password

[capture]
interface = eth0
packet_count = 100
remote_pcap_path = /tmp/capture.pcap
local_pcap_dir = ./captures
interval_seconds = 300
4. Run the agent
bash
python agent.py
📈 Anomaly Detection Logic
Based on unlabeled traffic

Uses Isolation Forest (unsupervised) to detect outliers

Labels each packet as:

0 = normal

1 = anomaly

Generated file: labeled_features.csv

🧪 Sample Output
timestamp	src_ip	dst_ip	src_port	dst_port	protocol	packet_length	anomaly
...	10.0.0.1	8.8.8.8	443	59843	TCP	64	0
...	10.0.0.2	192.168.5.4	5060	5060	UDP	1420	1

