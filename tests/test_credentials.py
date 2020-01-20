import os
import shutil

import mock
import tempfile
import ConfigParser
from datetime import datetime, timedelta
from dateutil.tz import tzlocal
from awssimplemfa import credentials

from tests import unittest, BaseEnvVar, create_client_creator, some_future_time


def get_expected_creds_from_response(response):
    expiration = response['Credentials']['Expiration']
    if isinstance(expiration, datetime):
        expiration = expiration.isoformat()
    return {
        'access_key': response['Credentials']['AccessKeyId'],
        'secret_key': response['Credentials']['SecretAccessKey'],
        'token': response['Credentials']['SessionToken'],
        'expiry_time': expiration
    }


def get_expected_creds_from_config(profile_name, config_file):
    config = ConfigParser.ConfigParser()
    config.readfp(open(config_file))
    profile_section = "profile {}".format(profile_name)
    return {
        'AccessKeyId': config.get(profile_section, 'aws_access_key_id'),
        'SecretAccessKey': config.get(profile_section, 'aws_secret_access_key'),
        'SessionToken': config.get(profile_section, 'aws_session_token'),
        'Expiration': config.get(profile_section, '_aws_session_expiration'),
    }


class TestSimpleMFACredentialFetcher(BaseEnvVar):
    def setUp(self):
        super(TestSimpleMFACredentialFetcher, self).setUp()
        self.source_creds = credentials.Credentials('a', 'b', 'c')
        self.mfa_serial = "mfa"
        self.prompter = mock.Mock(return_value='token-code')

    def test_no_cache(self):
        response = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': some_future_time().isoformat()
            },
        }
        client_creator = create_client_creator(with_response=response)
        refresher = credentials.SimpleMFACredentialFetcher(
            client_creator, self.source_creds, self.mfa_serial, mfa_prompter=self.prompter,
        )

        expected_response = get_expected_creds_from_response(response)
        response = refresher.fetch_credentials()

        self.assertEqual(response, expected_response)

    def test_retrieves_from_cache(self):
        date_in_future = datetime.utcnow() + timedelta(seconds=1000)
        utc_timestamp = date_in_future.isoformat() + 'Z'
        cache_key = (
            'ab1a4e3a5b3a855357eaf66f645e85c0f1147764'
        )
        cache = {
            cache_key: {
                'Credentials': {
                    'AccessKeyId': 'foo-cached',
                    'SecretAccessKey': 'bar-cached',
                    'SessionToken': 'baz-cached',
                    'Expiration': utc_timestamp,
                }
            }
        }
        client_creator = mock.Mock()
        refresher = credentials.SimpleMFACredentialFetcher(
            client_creator, self.source_creds, self.mfa_serial, mfa_prompter=self.prompter, cache=cache
        )

        expected_response = get_expected_creds_from_response(
            cache[cache_key]
        )
        response = refresher.fetch_credentials()

        self.assertEqual(response, expected_response)
        client_creator.assert_not_called()

    def test_simple_mfa_in_cache_but_expired(self):
        response = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': some_future_time().isoformat(),
            },
        }
        client_creator = create_client_creator(with_response=response)
        cache_key = (
            'ab1a4e3a5b3a855357eaf66f645e85c0f1147764'
        )
        cache = {
            cache_key: {
                'Credentials': {
                    'AccessKeyId': 'foo-cached',
                    'SecretAccessKey': 'bar-cached',
                    'SessionToken': 'baz-cached',
                    'Expiration': datetime.now(tzlocal()),
                }
            }
        }

        refresher = credentials.SimpleMFACredentialFetcher(
            client_creator, self.source_creds, self.mfa_serial, mfa_prompter=self.prompter, cache=cache
        )
        expected = get_expected_creds_from_response(response)
        response = refresher.fetch_credentials()

        self.assertEqual(response, expected)


class TestSimpleMFACredentialProvider(unittest.TestCase):
    def setUp(self):
        self.fake_config = {
            'profiles': {
                'development': {
                    'aws_access_key_id': 'akid',
                    'aws_secret_access_key': 'skid',
                    'mfa_serial': "mfa"
                }
            }
        }
        self.tempdir = tempfile.mkdtemp(prefix="")
        self.prompter = mock.Mock(return_value='token-code')

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def create_config_loader(self, with_config=None):
        if with_config is None:
            with_config = self.fake_config
        load_config = mock.Mock()
        load_config.return_value = with_config
        return load_config

    def test_simple_mfa_with_no_cache(self):
        response = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': some_future_time().isoformat()
            },
        }
        client_creator = create_client_creator(with_response=response)
        provider = credentials.SimpleMFAProvider(
            self.create_config_loader(),
            client_creator, cache={}, profile_name='development', prompter=self.prompter)

        creds = provider.load()

        self.assertEqual(creds.access_key, 'foo')
        self.assertEqual(creds.secret_key, 'bar')
        self.assertEqual(creds.token, 'baz')

    def test_simple_mfa_retrieves_from_cache(self):
        date_in_future = datetime.utcnow() + timedelta(seconds=1000)
        utc_timestamp = date_in_future.isoformat() + 'Z'

        cache_key = (
            'ab1a4e3a5b3a855357eaf66f645e85c0f1147764'
        )
        cache = {
            cache_key: {
                'Credentials': {
                    'AccessKeyId': 'foo-cached',
                    'SecretAccessKey': 'bar-cached',
                    'SessionToken': 'baz-cached',
                    'Expiration': utc_timestamp,
                }
            }
        }
        provider = credentials.SimpleMFAProvider(
            self.create_config_loader(), mock.Mock(),
            cache=cache, profile_name='development', prompter=self.prompter)

        creds = provider.load()

        self.assertEqual(creds.access_key, 'foo-cached')
        self.assertEqual(creds.secret_key, 'bar-cached')
        self.assertEqual(creds.token, 'baz-cached')

    def test_simple_mfa_in_cache_but_expired(self):
        expired_creds = datetime.now(tzlocal())
        valid_creds = expired_creds + timedelta(hours=1)
        response = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': valid_creds,
            },
        }
        client_creator = create_client_creator(with_response=response)
        cache_key = (
            'ab1a4e3a5b3a855357eaf66f645e85c0f1147764'
        )
        cache = {
            cache_key: {
                'Credentials': {
                    'AccessKeyId': 'foo-cached',
                    'SecretAccessKey': 'bar-cached',
                    'SessionToken': 'baz-cached',
                    'Expiration': expired_creds,
                }
            }
        }
        provider = credentials.SimpleMFAProvider(
            self.create_config_loader(), client_creator,
            cache=cache, profile_name='development', prompter=self.prompter)

        creds = provider.load()

        self.assertEqual(creds.access_key, 'foo')
        self.assertEqual(creds.secret_key, 'bar')
        self.assertEqual(creds.token, 'baz')

    def test_no_credentials_in_config(self):
        del self.fake_config['profiles']['development']['aws_access_key_id']
        del self.fake_config['profiles']['development']['aws_secret_access_key']
        provider = credentials.SimpleMFAProvider(
            self.create_config_loader(), mock.Mock(),
            cache={}, profile_name='development', prompter=self.prompter)
        with self.assertRaises(credentials.PartialCredentialsError):
            provider.load()

    def test_no_mfa_serial_in_config(self):
        del self.fake_config['profiles']['development']['mfa_serial']
        provider = credentials.SimpleMFAProvider(
            self.create_config_loader(), mock.Mock(),
            cache={}, profile_name='development', prompter=self.prompter)
        self.assertIsNone(provider.load())

    def test_simple_mfa_with_tmp_config(self):
        response = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': some_future_time().isoformat()
            },
        }
        profile_name = 'development'
        client_creator = create_client_creator(with_response=response)
        p = os.path.join(self.tempdir, "tmp_config_file")
        cache = credentials.SimpleMFACache(credentials.TempConfigWriter(p, profile_name, 'us-west-2'), {})
        provider = credentials.SimpleMFAProvider(
            self.create_config_loader(),
            client_creator, cache=cache,
            profile_name=profile_name, prompter=self.prompter)

        creds = provider.load()

        self.assertEqual(creds.access_key, 'foo')
        self.assertEqual(creds.secret_key, 'bar')
        self.assertEqual(creds.token, 'baz')
        self.assertEqual(response['Credentials'], get_expected_creds_from_config(profile_name, p))


class TestTempConfigWriter(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(prefix="")
        self.profile_name = "test"

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_write_with_non_exist_file(self):
        response = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': some_future_time().isoformat(),
            },
        }
        p = os.path.join(self.tempdir, "non_exist_config_file")
        writer = credentials.TempConfigWriter(p, self.profile_name, "us-west-2")
        writer.update(response)
        self.assertEqual(response['Credentials'], get_expected_creds_from_config(self.profile_name, p))

    def test_write_with_exist_file(self):
        response = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': some_future_time().isoformat(),
            },
        }
        p = os.path.join(self.tempdir, "exist_config_file")
        config = ConfigParser.ConfigParser()
        config.add_section("test")
        config.set("test", "foo", "bar")
        writer = credentials.TempConfigWriter(p, self.profile_name, "us-west-2")
        writer.update(response)
        self.assertEqual(response['Credentials'], get_expected_creds_from_config(self.profile_name, p))
        config2 = ConfigParser.ConfigParser()
        config2.readfp(open(p))
        self.assertEqual(config.get("test", "foo"), "bar")
