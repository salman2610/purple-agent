import pytest
from agent import collector

def test_collect_metrics():
    metrics = collector.collect_metrics()
    assert "cpu" in metrics
    assert 0 <= metrics["cpu"] <= 100
    assert "memory" in metrics
    assert 0 <= metrics["memory"] <= 100
    assert "disk" in metrics
    assert 0 <= metrics["disk"] <= 100
    assert "processes" in metrics
    assert isinstance(metrics["processes"], list)
