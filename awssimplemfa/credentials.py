import datetime
import getpass
import json
from copy import deepcopy
from hashlib import sha1

from botocore.credentials import CredentialProvider, CachedCredentialFetcher, Credentials, \
    create_mfa_serial_refresher, DeferredRefreshableCredentials, JSONFileCache
from botocore.exceptions import PartialCredentialsError
from dateutil.tz import tzlocal, os

CACHE_DIR = os.path.expanduser(os.path.join('~', '.aws', 'cli', 'cache', 'simple-mfa'))


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


class CredentialResolverBuilder(object):

    def __init__(self, resolver_creator):
        self.resolver_creator = resolver_creator

    def build(self, session, cache=None, region_name=None):
        resolver = self.resolver_creator(session, cache, region_name)
        profile_name = session.get_config_variable('profile') or 'default'
        if not cache:
            cache = JSONFileCache(CACHE_DIR)
        simple_mfa_provider = SimpleMFAProvider(
            lambda: session.full_config,
            _get_client_creator(session, region_name),
            cache, profile_name)
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
    METHOD = 'simple-sts-mfa'
    MFA_CONFIG_VAR = "mfa_serial"

    def __init__(self, load_config, client_creator, cache, profile_name,
                 prompter=getpass.getpass):
        self.cache = cache
        self._load_config = load_config
        self._client_creator = client_creator
        self._profile_name = profile_name
        self._prompter = prompter
        self._loaded_config = {}

    def load(self):
        self._loaded_config = self._load_config()
        profiles = self._loaded_config.get('profiles', {})
        profile = profiles.get(self._profile_name, {})
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
