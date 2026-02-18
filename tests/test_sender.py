import requests
from unittest.mock import patch

from agent import sender


@patch("requests.post")
def test_send_data(mock_post):
    mock_post.return_value.status_code = 200
    config = {
        "server_url": "http://fakeapi.test/post",
        "agent_id": "testagent",
        "auth_token": "testtoken-this-is-long-enough-for-sha256",
    }
    assert sender.send_data({"test": "data"}, config) is True
    mock_post.assert_called_once()
