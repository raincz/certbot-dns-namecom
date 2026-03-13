"""DNS Authenticator for Name.com."""
import logging
from typing import Any
from typing import Callable
from typing import cast
from typing import Optional

import requests

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

API_URL = 'https://api.name.com'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Name.com

    This Authenticator uses the Name.com API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are ' + \
                  'using Name.com for DNS).'
    ttl = 300

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Name.com credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Name.com API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'Name.com credentials INI file',
            {
                'username': 'Username for Name.com account',
                'token': 'API token for Name.com account',
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_namecom_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_namecom_client().del_txt_record(domain, validation_name, validation)

    def _get_namecom_client(self) -> "_NameComClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _NameComClient(
            cast(str, self.credentials.conf('username')),
            cast(str, self.credentials.conf('token')),
        )


class _NameComClient:
    """
    Encapsulates all communication with the Name.com API.
    """

    def __init__(self, username: str, token: str) -> None:
        self.session = requests.Session()
        self.session.auth = (username, token)
        self.session.headers.update({
            'Content-Type': 'application/json',
        })

    def add_txt_record(self, domain_name: str, record_name: str, record_content: str,
                       record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (minimum 300 for Name.com).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Name.com API
        """

        domain = self._find_domain(domain_name)
        host = self._compute_record_host(domain, record_name)

        try:
            response = self.session.post(
                f'{API_URL}/v4/domains/{domain}/records',
                json={
                    'host': host,
                    'type': 'TXT',
                    'answer': record_content,
                    'ttl': record_ttl,
                },
            )
            response.raise_for_status()
            logger.debug('Successfully added TXT record for %s', record_name)
        except requests.exceptions.RequestException as e:
            hint = ''
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 401:
                    hint = ' (Did you provide valid API credentials?)'
                else:
                    hint = f' (Response: {e.response.text})'
            logger.debug('Error adding TXT record using the Name.com API: %s', e)
            raise errors.PluginError(
                f'Error adding TXT record using the Name.com API: {e}{hint}'
            )

    def del_txt_record(self, domain_name: str, record_name: str, record_content: str) -> None:
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            domain = self._find_domain(domain_name)
        except errors.PluginError as e:
            logger.debug('Error finding domain: %s', e)
            return

        try:
            records = self._list_records(domain)
            host = self._compute_record_host(domain, record_name)

            matching_records = [
                r for r in records
                if r.get('type') == 'TXT'
                and r.get('host') == host
                and r.get('answer') == record_content
            ]
        except requests.exceptions.RequestException as e:
            logger.debug('Error getting DNS records using the Name.com API: %s', e)
            return

        for record in matching_records:
            try:
                record_id = record['id']
                logger.debug('Removing TXT record with id: %s', record_id)
                response = self.session.delete(
                    f'{API_URL}/v4/domains/{domain}/records/{record_id}',
                )
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                logger.warning('Error deleting TXT record %s using the Name.com API: %s',
                               record.get('id'), e)

    def _find_domain(self, domain_name: str) -> str:
        """
        Find the domain name for a given FQDN.

        :param str domain_name: The domain name for which to find the base domain.
        :returns: The base domain name, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if no matching domain is found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        for guess in domain_name_guesses:
            try:
                response = self.session.get(f'{API_URL}/v4/domains/{guess}')
                if response.status_code == 200:
                    logger.debug('Found base domain for %s using name %s', domain_name, guess)
                    return guess
            except requests.exceptions.RequestException as e:
                logger.debug('Error looking up domain %s: %s', guess, e)

        raise errors.PluginError(
            f'Unable to determine base domain for {domain_name} using names: '
            f'{domain_name_guesses}.'
        )

    def _list_records(self, domain: str) -> list:
        """
        List all DNS records for a domain.

        :param str domain: The domain name.
        :returns: List of record dicts.
        :rtype: list
        """

        response = self.session.get(f'{API_URL}/v4/domains/{domain}/records')
        response.raise_for_status()
        return response.json().get('records', [])

    @staticmethod
    def _compute_record_host(domain: str, full_record_name: str) -> str:
        # Name.com uses relative hostnames (without the domain suffix).
        # e.g., for "_acme-challenge.example.com" on domain "example.com",
        # the host is "_acme-challenge".
        suffix = '.' + domain
        if full_record_name.endswith(suffix):
            return full_record_name[:-len(suffix)]
        return full_record_name
