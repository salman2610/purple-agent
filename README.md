🟣 Purple Agent

Python Modular Server Monitoring Agent for AI-Powered Threat Detection and Security Analytics

🧩 Overview

Purple Agent collects real-time system metrics, monitors critical logs, tracks network activity, and securely sends collected data to a centralized dashboard for threat detection and anomaly analysis.
It’s built with a modular architecture for scalability and ease of maintenance.

🚀 Features

CPU, memory, disk usage, process listing, and uptime monitoring

Real-time log file monitoring for failed/successful login detection

Network connection tracking to identify suspicious activity

Secure authenticated communication using JWT tokens

Modularized codebase enabling easy extension

Designed for deployment as a systemd service for persistence

🧰 Getting Started
Prerequisites

Python 3.8+

Linux server (Ubuntu/Debian/CentOS recommended)

Access to install system packages and configure services

Installation

1. Clone the repository

git clone https://github.com/yourusername/purple-agent.git
cd purple-agent


2. Create and activate a virtual environment

python3 -m venv venv
source venv/bin/activate


3. Install dependencies

pip install -r requirements.txt


4. Configure the agent
Edit config/config.json with your dashboard API URL, agent ID, authentication token, scan interval, and monitored log/file paths.

▶️ Running the Agent

Start the agent manually with:

python -m agent.main

🧠 Deployment as a systemd Service

Create a service file at /etc/systemd/system/purple-agent.service:

[Unit]
Description=Purple Agent Monitoring Service
After=network.target

[Service]
User=root
WorkingDirectory=/path/to/purple-agent
ExecStart=/path/to/purple-agent/venv/bin/python -m agent.main
Restart=always

[Install]
WantedBy=multi-user.target


Then reload and enable the service:

sudo systemctl daemon-reload
sudo systemctl enable purple-agent
sudo systemctl start purple-agent


Check service status:

sudo systemctl status purple-agent

⚙️ Configuration

Example config/config.json:

{
  "server_url": "https://your-dashboard-api.example.com/api/agent",
  "agent_id": "agent-001",
  "auth_token": "securetokenhere",
  "scan_interval": 60,
  "log_paths": ["/var/log/auth.log", "/var/log/syslog"],
  "integrity_dirs": ["/etc", "/var/www", "/usr/bin"]
}


Configuration Options

server_url: URL of the dashboard API endpoint

agent_id: Unique ID for this agent instance

auth_token: JWT secret token for agent authentication

scan_interval: Seconds between metric scans

log_paths: List of log files to watch in real-time

integrity_dirs: Directories for file integrity monitoring

🧩 Contribution

Contributions are welcome!
Please open issues or pull requests for bug fixes, features, or enhancements.

🩺 Troubleshooting

Ensure dependencies are installed and the Python environment is activated.

Confirm the agent has permission to read specified log files.

Check systemd logs:

journalctl -u purple-agent -f


Verify dashboard URL and authentication tokens in the config.

Enable debug logging in source for detailed output if needed.

📜 License

MIT License
