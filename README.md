# Purple Agent

Python modular server monitoring agent for AI-powered threat detection.

## Installation

1. Clone the repo.
2. Create a Python virtual environment and activate it.
3. Install dependencies:

pip install -r requirements.txt

text

4. Edit `config/config.json` with your server API URL, agent ID, and token.

## Running the Agent

python -m agent.main

text

## Features

- Collects system metrics (CPU, memory, disk, processes).
- Monitors important log files in real-time.
- Tracks active network connections.
- Sends encrypted and authenticated data to central server.
- Modular code structure for easy extension.
