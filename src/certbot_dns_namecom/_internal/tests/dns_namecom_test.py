"""Tests for certbot_dns_namecom._internal.dns_namecom."""

import sys
import unittest
from unittest import mock

import pytest
import requests

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

USERNAME = 'myuser'
TOKEN = 'a-token'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_namecom._internal.dns_namecom import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"namecom_username": USERNAME, "namecom_token": TOKEN}, path)

        self.config = mock.MagicMock(namecom_credentials=path,
                                     namecom_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "namecom")

        self.mock_client = mock.MagicMock()
        # _get_namecom_client | pylint: disable=protected-access
        setattr(self.auth, '_get_namecom_client',
            mock.MagicMock(return_value=self.mock_client))

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY, 300)]
        assert expected == self.mock_client.mock_calls

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY)]
        assert expected == self.mock_client.mock_calls


class NameComClientTest(unittest.TestCase):

    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"
    record_ttl = 300

    def setUp(self):
        from certbot_dns_namecom._internal.dns_namecom import _NameComClient

        self.client = _NameComClient(USERNAME, TOKEN)

    @mock.patch('requests.Session.get')
    @mock.patch('requests.Session.post')
    def test_add_txt_record(self, mock_post, mock_get):
        mock_get.return_value = mock.MagicMock(status_code=200)
        mock_post.return_value = mock.MagicMock(status_code=200)
        mock_post.return_value.raise_for_status = mock.MagicMock()

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        mock_post.assert_called_once_with(
            f'https://api.name.com/v4/domains/{DOMAIN}/records',
            json={
                'host': self.record_prefix,
                'type': 'TXT',
                'answer': self.record_content,
                'ttl': self.record_ttl,
            },
        )

    @mock.patch('requests.Session.get')
    @mock.patch('requests.Session.post')
    def test_add_txt_record_error(self, mock_post, mock_get):
        mock_get.return_value = mock.MagicMock(status_code=200)
        mock_post.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError()

        with pytest.raises(errors.PluginError):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                       self.record_ttl)

    @mock.patch('requests.Session.get')
    def test_add_txt_record_domain_not_found(self, mock_get):
        mock_get.return_value = mock.MagicMock(status_code=404)

        with pytest.raises(errors.PluginError):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                       self.record_ttl)

    @mock.patch('requests.Session.get')
    @mock.patch('requests.Session.delete')
    def test_del_txt_record(self, mock_delete, mock_get):
        domain_response = mock.MagicMock(status_code=200)
        records_response = mock.MagicMock(status_code=200)
        records_response.json.return_value = {
            'records': [
                {'id': 1, 'type': 'TXT', 'host': 'DIFFERENT', 'answer': self.record_content},
                {'id': 2, 'type': 'TXT', 'host': self.record_prefix, 'answer': self.record_content},
                {'id': 3, 'type': 'TXT', 'host': self.record_prefix, 'answer': 'DIFFERENT'},
            ]
        }
        records_response.raise_for_status = mock.MagicMock()
        mock_get.side_effect = [domain_response, records_response]
        mock_delete.return_value = mock.MagicMock(status_code=200)
        mock_delete.return_value.raise_for_status = mock.MagicMock()

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        mock_delete.assert_called_once_with(
            f'https://api.name.com/v4/domains/{DOMAIN}/records/2',
        )

    @mock.patch('requests.Session.get')
    def test_del_txt_record_domain_not_found(self, mock_get):
        mock_get.return_value = mock.MagicMock(status_code=404)

        # Should not raise, just log
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    @mock.patch('requests.Session.get')
    @mock.patch('requests.Session.delete')
    def test_del_txt_record_error_deleting(self, mock_delete, mock_get):
        domain_response = mock.MagicMock(status_code=200)
        records_response = mock.MagicMock(status_code=200)
        records_response.json.return_value = {
            'records': [
                {'id': 2, 'type': 'TXT', 'host': self.record_prefix, 'answer': self.record_content},
            ]
        }
        records_response.raise_for_status = mock.MagicMock()
        mock_get.side_effect = [domain_response, records_response]
        mock_delete.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError()

        # Should not raise, just log warning
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
