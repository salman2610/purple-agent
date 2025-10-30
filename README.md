Purple Agent
Python modular server monitoring agent for AI-powered threat detection and security analytics.

Overview
Purple Agent collects real-time system metrics, monitors critical logs, tracks network activity, and securely sends collected data to a centralized dashboard for threat detection and anomaly analysis. Designed with modular architecture for scalability and ease of maintenance.

Features
CPU, memory, disk usage, process listing, and uptime monitoring

Real-time log file monitoring for failed/successful login detection

Network connection tracking to identify suspicious activity

Secure authenticated communication with JWT tokens

Modularized codebase enabling easy extension

Designed for deployment as a systemd service for persistence

Getting Started
Prerequisites
Python 3.8+

Linux server (Ubuntu/Debian/CentOS recommended)

Access to install system packages and configure services

Installation
Clone the repository:

bash
git clone https://github.com/yourusername/purple-agent.git
cd purple-agent
Create and activate a Python virtual environment:

bash
python3 -m venv venv
source venv/bin/activate
Install dependencies:

bash
pip install -r requirements.txt
Configure agent settings:

Edit config/config.json with your dashboard API URL, agent ID, authentication token, scan interval, and monitored log/file paths.

Running the Agent
Start the agent manually with:

bash
python -m agent.main
Deployment as a systemd Service
Create a purple-agent.service file in /etc/systemd/system/ with contents:

text
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
Reload systemd and enable service:

bash
sudo systemctl daemon-reload
sudo systemctl enable purple-agent
sudo systemctl start purple-agent
Check status:

bash
sudo systemctl status purple-agent
Configuration
Example config/config.json:

json
{
  "server_url": "https://your-dashboard-api.example.com/api/agent",
  "agent_id": "agent-001",
  "auth_token": "securetokenhere",
  "scan_interval": 60,
  "log_paths": ["/var/log/auth.log", "/var/log/syslog"],
  "integrity_dirs": ["/etc", "/var/www", "/usr/bin"]
}
server_url: URL of dashboard API endpoint.

agent_id: Unique ID for this agent instance.

auth_token: JWT secret token for agent authentication.

scan_interval: Seconds between metric scans.

log_paths: List of log files to watch in real-time.

integrity_dirs: Directories for file integrity monitoring.

Contribution
Contributions are welcome! Please open issues or pull requests for bug fixes, features, or enhancements.

Troubleshooting
Make sure dependencies are installed and python environment is activated.

Confirm the agent has permission to read specified log files.

Check systemd logs with journalctl -u purple-agent -f.

Verify dashboard URL and tokens in config.

Enable debug logging by modifying the source if needed.

License
MIT License
