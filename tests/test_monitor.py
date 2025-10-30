import pytest
from agent import monitor
import os
import tempfile

def test_get_log_events():
    # Create temp log files
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"Failed password for user\nAccepted password for user\n")
        f.flush()
        logs = monitor.get_log_events([f.name])
        assert "failed_logins" in logs["log_events"][f.name]
        assert logs["log_events"][f.name]["failed_logins"] >= 1
        assert logs["log_events"][f.name]["successful_logins"] >= 1
    os.remove(f.name)

