import jwt
import requests


def send_data(data, config):
    try:
        token = jwt.encode(
            {"agent_id": config["agent_id"]},
            config["auth_token"],
            algorithm="HS256",
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        response = requests.post(config["server_url"], json=data, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"Failed sending data: {response.status_code} {response.text}")
            return False

        print("Data sent successfully")
        return True
    except (requests.RequestException, KeyError, ValueError) as exc:
        print(f"Error sending data: {exc}")
        return False
