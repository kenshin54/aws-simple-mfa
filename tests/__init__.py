import unittest
import mock
from datetime import datetime, timedelta
from dateutil.tz import tzlocal


class BaseEnvVar(unittest.TestCase):
    def setUp(self):
        self.environ = {}
        self.environ_patch = mock.patch('os.environ', self.environ)
        self.environ_patch.start()

    def tearDown(self):
        self.environ_patch.stop()


def create_client_creator(with_response):
    client = mock.Mock()
    if isinstance(with_response, list):
        client.get_session_token.side_effect = with_response
    else:
        client.get_session_token.return_value = with_response
    return mock.Mock(return_value=client)


def some_future_time():
    return datetime.now(tzlocal()) + timedelta(hours=24)
