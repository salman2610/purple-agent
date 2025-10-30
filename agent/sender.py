import requests
import jwt
import json

def send_data(data, config):
    try:
        token = jwt.encode({"agent_id": config["agent_id"]}, config["auth_token"], algorithm="HS256")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.post(config["server_url"], json=data, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"Failed sending data: {response.status_code} {response.text}")
        else:
            print("Data sent successfully")
    except Exception as e:
        print(f"Error sending data: {e}")
