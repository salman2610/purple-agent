import psutil
import time

def collect_metrics():
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        users = [u.name for u in psutil.users()]
        uptime = int(time.time() - psutil.boot_time())
        processes = [p.info for p in psutil.process_iter(['pid', 'name', 'username'])]
        return {
            "cpu": cpu,
            "memory": mem.percent,
            "disk": disk.percent,
            "users": users,
            "uptime": uptime,
            "processes": processes
        }
    except Exception as e:
        return {"error": f"Metric collection error: {e}"}
