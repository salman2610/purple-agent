#!/bin/bash

echo "🚀 Submitting test data to PurpleTeam Dashboard..."

# Get a fresh token
echo "🔐 Getting authentication token..."
TOKEN_RESPONSE=$(curl -s -X POST "http://localhost:8000/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=adminpass")

TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    echo "❌ Failed to get token. Response: $TOKEN_RESPONSE"
    echo "💡 Make sure:"
    echo "   - Backend is running on http://localhost:8000"
    echo "   - Admin user exists (username: admin, password: adminpass)"
    echo "   - Database is connected"
    exit 1
fi

echo "✅ Token obtained successfully: ${TOKEN:0:20}..."

# Function to submit data and check response
submit_data() {
    local description="$1"
    local data="$2"
    
    echo -n "$description... "
    
    RESPONSE=$(curl -s -X POST "http://localhost:8000/agent/data" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$data")
    
    if echo "$RESPONSE" | grep -q "message.*Agent data received"; then
        echo "✅ Success"
        echo "   📊 Response: $RESPONSE"
    else
        echo "❌ Failed: $RESPONSE"
    fi
}

# Test 1: High CPU alert (will trigger alert)
submit_data "📊 High CPU data" '{
    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "hostname": "high-cpu-server",
    "cpu_usage": 95.8,
    "memory_usage": 45.2,
    "disk_usage": 32.7,
    "network_activity": {
        "bytes_sent": 2345678988,
        "bytes_received": 9876543245887
    },
    "processes": [
        {"pid": 1, "name": "systemd", "cpu": 85.1, "memory": 89.5},
        {"pid": 101, "name": "stress_test", "cpu": 85.2, "memory": 2.1}
    ]
}'

sleep 1

# Test 2: High Memory alert (will trigger alert)
submit_data "💾 High Memory data" '{
    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "hostname": "high-memory-server",
    "cpu_usage": 35.4,
    "memory_usage": 91.7,
    "disk_usage": 28.9,
    "network_activity": {
        "bytes_sent": 12345678,
        "bytes_received": 87654321
    },
    "processes": [
        {"pid": 1, "name": "systemd", "cpu": 0.1, "memory": 0.5},
        {"pid": 102, "name": "memory_leak", "cpu": 5.2, "memory": 82.1}
    ]
}'

sleep 1

# Test 3: Critical Disk usage (will trigger alert)
submit_data "💽 High Disk usage data" '{
    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "hostname": "full-disk-server",
    "cpu_usage": 25.1,
    "memory_usage": 38.9,
    "disk_usage": 96.3,
    "network_activity": {
        "bytes_sent": 34567890,
        "bytes_received": 76543210
    },
    "processes": [
        {"pid": 1, "name": "systemd", "cpu": 0.1, "memory": 0.5},
        {"pid": 103, "name": "log_cleaner", "cpu": 12.3, "memory": 4.2}
    ]
}'

sleep 1

# Test 4: Suspicious process (will trigger security alert)
submit_data "🛡️ Suspicious process data" '{
    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "hostname": "compromised-server",
    "cpu_usage": 78.9,
    "memory_usage": 65.4,
    "disk_usage": 45.6,
    "network_activity": {
        "bytes_sent": 56789012,
        "bytes_received": 23456789
    },
    "processes": [
        {"pid": 1, "name": "systemd", "cpu": 0.1, "memory": 0.5},
        {"pid": 666, "name": "backdoor_malware", "cpu": 65.4, "memory": 32.1},
        {"pid": 667, "name": "crypto_miner", "cpu": 12.3, "memory": 28.9}
    ]
}'

echo ""
echo "🎉 Test data submission complete!"
echo ""
echo "📋 Now check your:"
echo "   🔧 Backend Console - Should show '🚨 Alert triggered' messages"
echo "   🖥️  Frontend Dashboard - Should show metrics and incidents"
echo "   📊 Alerts Tab - Should show multiple incidents"
echo ""
echo "🔍 Quick verification commands:"
echo "   curl -s -H \"Authorization: Bearer $TOKEN\" \"http://localhost:8000/agent/data/latest\" | jq ."
echo "   curl -s -H \"Authorization: Bearer $TOKEN\" \"http://localhost:8000/incidents\" | jq ."
