import os
from datetime import datetime, timedelta

import mock
from botocore.credentials import Credentials
from dateutil.tz import tzlocal
from awssimplemfa import credentials

from tests import unittest

# Passed to session to keep it from finding default config file
TESTENVVARS = {'config_file': (None, 'AWS_CONFIG_FILE', None)}


raw_metadata = {
    'foobar': {
        'Code': 'Success',
        'LastUpdated': '2012-12-03T14:38:21Z',
        'AccessKeyId': 'foo',
        'SecretAccessKey': 'bar',
        'Token': 'foobar',
        'Expiration': '2012-12-03T20:48:03Z',
        'Type': 'AWS-HMAC'
    }
}
post_processed_metadata = {
    'role_name': 'foobar',
    'access_key': raw_metadata['foobar']['AccessKeyId'],
    'secret_key': raw_metadata['foobar']['SecretAccessKey'],
    'token': raw_metadata['foobar']['Token'],
    'expiry_time': raw_metadata['foobar']['Expiration'],
}


def path(filename):
    return os.path.join(os.path.dirname(__file__), 'cfg', filename)


class TestSimpleMFACredentialProvider(unittest.TestCase):

    maxDiff = None

    def setUp(self):
        self.fake_config = {
            'profiles': {
                'development': {
                    'aws_access_key_id': 'akid',
                    'aws_secret_access_key': 'skid',
                    'mfa_serial': "mfa_serial"
                }
            }
        }

    def create_config_loader(self, with_config=None):
        if with_config is None:
            with_config = self.fake_config
        load_config = mock.Mock()
        load_config.return_value = with_config
        return load_config

    def create_client_creator(self, with_response):
        # Create a mock sts client that returns a specific response
        # for assume_role.
        client = mock.Mock()
        if isinstance(with_response, list):
            client.get_session_token.side_effect = with_response
        else:
            client.get_session_token.return_value = with_response
        return mock.Mock(return_value=client)

    def some_future_time(self):
        timeobj = datetime.now(tzlocal())
        return timeobj + timedelta(hours=24)

    def test_simple_mfa_with_no_cache(self):
        response = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': self.some_future_time().isoformat()
            },
        }
        client_creator = self.create_client_creator(with_response=response)
        prompter = mock.Mock(return_value='token-code')
        provider = credentials.SimpleMFAProvider(
            self.create_config_loader(),
            client_creator, cache={}, profile_name='development', prompter=prompter)

        creds = provider.load()

        self.assertEqual(creds.access_key, 'foo')
        self.assertEqual(creds.secret_key, 'bar')
        self.assertEqual(creds.token, 'baz')


class ProfileProvider(object):
    METHOD = 'fake'

    def __init__(self, profile_name):
        self._profile_name = profile_name

    def load(self):
        return Credentials(
            '%s-access-key' % self._profile_name,
            '%s-secret-key' % self._profile_name,
            '%s-token' % self._profile_name,
            self.METHOD
        )
