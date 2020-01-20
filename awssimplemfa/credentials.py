import os
import datetime
import getpass
import json
try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser
from copy import deepcopy
from hashlib import sha1

from botocore.credentials import CredentialProvider, CachedCredentialFetcher, Credentials, \
    create_mfa_serial_refresher, DeferredRefreshableCredentials, JSONFileCache
from botocore.exceptions import PartialCredentialsError
from dateutil.tz import tzlocal, os

CACHE_DIR = os.path.expanduser(os.path.join('~', '.aws', 'cli', 'cache', 'simple-mfa'))
DEFAULT_TMP_CONFIG_FILE = os.path.expanduser(os.path.join('~', '.aws', 'simple_mfa_tmp_config'))


def _local_now():
    return datetime.datetime.now(tzlocal())


def _get_client_creator(session, region_name):
    def client_creator(service_name, **kwargs):
        create_client_kwargs = {
            'region_name': region_name
        }
        create_client_kwargs.update(**kwargs)
        return session.create_client(service_name, **create_client_kwargs)

    return client_creator


class TempConfigWriter(object):
    def __init__(self, tmp_config_file, profile_name, region):
        self._tmp_config_file = tmp_config_file
        self._profile_name = profile_name
        self._region = region

    def update(self, value):
        config = ConfigParser()
        if os.path.exists(self._tmp_config_file):
            config.readfp(open(self._tmp_config_file))

        profile_section = "profile {}".format(self._profile_name)
        config.add_section(profile_section)
        config.set(profile_section, 'region', self._region)
        credentials = value['Credentials']
        config.set(profile_section, 'aws_access_key_id', credentials['AccessKeyId'])
        config.set(profile_section, 'aws_secret_access_key', credentials['SecretAccessKey'])
        config.set(profile_section, 'aws_session_token', credentials['SessionToken'])
        config.set(profile_section, '_aws_session_expiration', credentials['Expiration'])

        with open(self._tmp_config_file, 'w') as configfile:
            config.write(configfile)


class SimpleMFACache(object):

    def __init__(self, tmp_config_writer, json_file_cache):
        self._tmp_config_writer = tmp_config_writer
        self._json_file_cache = json_file_cache

    def __contains__(self, cache_key):
        return cache_key in self._json_file_cache

    def __getitem__(self, cache_key):
        return self._json_file_cache[cache_key]

    def __setitem__(self, cache_key, value):
        self._json_file_cache[cache_key] = value
        self._tmp_config_writer.update(value)


class CredentialResolverBuilder(object):

    def __init__(self, resolver_creator):
        self.resolver_creator = resolver_creator

    def build(self, session, cache=None, region_name=None):
        resolver = self.resolver_creator(session, cache, region_name)
        profile_name = session.get_config_variable('profile') or 'default'
        simple_mfa_provider = SimpleMFAProvider(
            lambda: session.full_config,
            _get_client_creator(session, region_name),
            cache, profile_name, enable_cache_fallback=True)
        resolver.insert_after("assume-role", simple_mfa_provider)
        return resolver


class SimpleMFACredentialFetcher(CachedCredentialFetcher):
    def __init__(self, client_creator,
                 source_credentials,
                 mfa_serial,
                 extra_args=None, mfa_prompter=None, cache=None,
                 expiry_window_seconds=None):
        self._client_creator = client_creator
        self._source_credentials = source_credentials
        self.mfa_serial = mfa_serial
        if extra_args is None:
            self._kwargs = {}
        else:
            self._kwargs = deepcopy(extra_args)
        self._kwargs['SerialNumber'] = self.mfa_serial
        self._mfa_prompter = mfa_prompter
        if self._mfa_prompter is None:
            self._mfa_prompter = getpass.getpass

        super(SimpleMFACredentialFetcher, self).__init__(
            cache, expiry_window_seconds
        )

    def _create_cache_key(self):
        args = deepcopy(self._kwargs)
        args = json.dumps(args, sort_keys=True)
        argument_hash = sha1(args.encode('utf-8')).hexdigest()
        return self._make_file_safe(argument_hash)

    def _get_credentials(self):
        kwargs = self._build_kwargs()
        client = self._create_client()
        return client.get_session_token(**kwargs)

    def _build_kwargs(self):
        kwargs = deepcopy(self._kwargs)
        prompt = 'Enter MFA code for %s: ' % self.mfa_serial
        token_code = self._mfa_prompter(prompt)
        kwargs['SerialNumber'] = self.mfa_serial
        kwargs['TokenCode'] = token_code

        duration_seconds = kwargs.get('DurationSeconds')

        if duration_seconds is not None:
            kwargs['DurationSeconds'] = duration_seconds
        return kwargs

    def _create_client(self):
        frozen_credentials = self._source_credentials.get_frozen_credentials()
        return self._client_creator(
            'sts',
            aws_access_key_id=frozen_credentials.access_key,
            aws_secret_access_key=frozen_credentials.secret_key,
            aws_session_token=frozen_credentials.token,
        )


class SimpleMFAProvider(CredentialProvider):
    METHOD = 'simple-mfa'
    MFA_CONFIG_VAR = "mfa_serial"
    TMP_SESSION_CONFIG_FILE_VAR = "tmp_config_file"

    def __init__(self, load_config, client_creator, cache, profile_name,
                 enable_cache_fallback=False, prompter=getpass.getpass):
        self.cache = cache
        self._load_config = load_config
        self._client_creator = client_creator
        self._profile_name = profile_name
        self._enable_cache_fallback = enable_cache_fallback
        self._prompter = prompter
        self._loaded_config = {}

    def load(self):
        self._loaded_config = self._load_config()
        profiles = self._loaded_config.get('profiles', {})
        profile = profiles.get(self._profile_name, {})
        tmp_config_file = profile.get(self.TMP_SESSION_CONFIG_FILE_VAR, DEFAULT_TMP_CONFIG_FILE)
        if self.cache is None and self._enable_cache_fallback:
            if tmp_config_file:
                self.cache = SimpleMFACache(
                    TempConfigWriter(tmp_config_file, self._profile_name, profile.get('region')),
                    JSONFileCache(CACHE_DIR))
            else:
                self.cache = JSONFileCache(CACHE_DIR)
        if self._has_mfa_config_vars(profile):
            return self._load_creds(profile)

    def _has_mfa_config_vars(self, profile):
        return self.MFA_CONFIG_VAR in profile

    def _load_creds(self, profile):
        source_credentials = self._resolve_static_credentials_from_profile(profile)
        fetcher = SimpleMFACredentialFetcher(
            client_creator=self._client_creator,
            source_credentials=source_credentials,
            mfa_serial=profile[self.MFA_CONFIG_VAR],
            mfa_prompter=self._prompter,
            cache=self.cache,
        )

        refresher = create_mfa_serial_refresher(fetcher.fetch_credentials)
        return DeferredRefreshableCredentials(
            method=self.METHOD,
            refresh_using=refresher,
            time_fetcher=_local_now
        )

    def _resolve_static_credentials_from_profile(self, profile):
        try:
            return Credentials(
                access_key=profile['aws_access_key_id'],
                secret_key=profile['aws_secret_access_key'],
                token=profile.get('aws_session_token')
            )
        except KeyError as e:
            raise PartialCredentialsError(
                provider=self.METHOD, cred_var=str(e))
