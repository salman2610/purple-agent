import requests

url = "http://localhost:8000/agent/data"
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTc2MTgyNzg0MH0.Qi28ibtK4kZb6PxT4E-w0W4UnSsusjVQKbSkABGcOUM"

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

json_data = {
    "timestamp": "2025-10-31T10:00:00Z",
    "hostname": "host1",
    "cpu_usage": 55.5,
    "memory_usage": 70.2,
    "disk_usage": 80.1,
    "network_activity": {
        "bytes_sent": 123456,
        "bytes_received": 654321
    },
    "processes": [
        {"pid": 123, "name": "python", "cpu": 10.5, "memory": 20.1},
        {"pid": 456, "name": "nginx", "cpu": 5.0, "memory": 10.2}
    ],
    "suspicious_activity": []
}

response = requests.post(url, json=json_data, headers=headers)
print(response.status_code)
print(response.json())
