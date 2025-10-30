import axios from "axios";

const API_BASE = "http://localhost:8000";
const token =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTc2MTgxOTA5NH0.dhQGDG994skpHijTt_I_cvM-Xt686swtjq4yF7M7R_Y";

const sampleData = {
  timestamp: new Date().toISOString(),
  hostname: "sample-host",
  cpu_usage: 23.0,
  memory_usage: 14.0,
  disk_usage: 66.5,
  network_activity: {
    bytes_sent: 986059,
    bytes_received: 576264,
  },
  processes: [
    { pid: 1, name: "systemd", cpu: 0.1, memory: 0.5 },
    { pid: 2, name: "bash", cpu: 0.2, memory: 0.3 },
  ],
};

axios
  .post(`${API_BASE}/agent/data`, sampleData, {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  })
  .then((response) => console.log("Data submitted:", response.data))
  .catch((error) =>
    console.error("Error submitting data:", error.response?.data || error.message)
  );
