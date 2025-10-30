// Save as criticalIncidentSubmit.js
import axios from "axios";

const API_BASE = "http://localhost:8000";
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTc2MTgyNzg0MH0.Qi28ibtK4kZb6PxT4E-w0W4UnSsusjVQKbSkABGcOUM";

const criticalIncident = {
  timestamp: "2025-10-30T12:57:42.963Z",
  hostname: "critical-prod-db1",
  cpu_usage: 98.7,
  memory_usage: 97.4,
  disk_usage: 96.3,
  network_activity: {
    bytes_sent: 1459802347,
    bytes_received: 2782048370
  },
  processes: [
    { pid: 7730, name: "unknown_malware", cpu: 75.3, memory: 83.1 },
    { pid: 1, name: "systemd", cpu: 0.1, memory: 0.5 },
    { pid: 7502, name: "encryptor_ransom", cpu: 10.5, memory: 10.1 }
  ],
  suspicious_activity: [
    {
      type: "file_encryption",
      files_affected: 25431,
      locations: ["/etc/", "/var/lib/", "/home/"]
    },
    {
      type: "network_scanning",
      target_ips: ["10.0.10.1", "10.0.10.2", "10.0.10.3"]
    }
  ]
};

axios.post(`${API_BASE}/agent/data`, criticalIncident, {
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json"
  }
}).then(response => {
  console.log("Critical incident submitted!", response.data);
}).catch(error => {
  console.error("Submission failed:", error.response?.data || error.message);
});
