import pytest
import requests
from agent import sender
from unittest.mock import patch

@patch('requests.post')
def test_send_data(mock_post):
    mock_post.return_value.status_code = 200
    config = {
        "server_url": "http://fakeapi.test/post",
        "agent_id": "testagent",
        "auth_token": "testtoken"
    }
    sender.send_data({"test": "data"}, config)
    mock_post.assert_called_once()
