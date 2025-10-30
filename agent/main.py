import time
import json
import signal
import sys

from agent.collector import collect_metrics
from agent.monitor import get_log_events, start_log_monitor
from agent.network import get_network_activity
from agent.sender import send_data

STOP_EVENT = False

def signal_handler(sig, frame):
    global STOP_EVENT
    print("Signal received. Exiting gracefully...")
    STOP_EVENT = True

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def run_agent():
    with open('config/config.json') as f:
        config = json.load(f)

    # Start log monitoring in background thread (real-time monitoring)
    log_thread = start_log_monitor(config.get("log_paths", []))

    try:
        while not STOP_EVENT:
            data = {
                "agent_id": config["agent_id"],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            data.update(collect_metrics())
            data.update(get_log_events(config.get("log_paths", [])))
            data.update(get_network_activity())
            
            send_data(data, config)
            time.sleep(config.get("scan_interval", 60))
    except Exception as e:
        print(f"Error in main loop: {e}")
    finally:
        log_thread.stop()
        log_thread.join()
        print("Agent stopped.")

if __name__ == "__main__":
    run_agent()
