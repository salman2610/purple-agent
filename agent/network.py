import psutil


def get_network_activity():
    connections = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                connections.append({
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "pid": conn.pid,
                })
    except (psutil.Error, OSError) as exc:
        return {"active_connections": connections, "network_error": str(exc)}

    return {"active_connections": connections}
