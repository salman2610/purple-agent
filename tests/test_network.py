from agent import network

def test_get_network_activity():
    data = network.get_network_activity()
    assert "active_connections" in data
    assert isinstance(data["active_connections"], list)
