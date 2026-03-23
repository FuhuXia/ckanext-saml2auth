# encoding: utf-8

"""
Copyright (c) 2020 Keitaro AB

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
from unittest import mock

import pytest
from saml2.xmldsig import SIG_RSA_SHA256
from ckanext.saml2auth.views.saml2auth import saml2login


here = os.path.dirname(os.path.abspath(__file__))
extras_folder = os.path.join(here, 'extras')


@pytest.mark.ckan_config(u'ckanext.saml2auth.requested_authn_context_comparison', 'bad_value')
@pytest.mark.ckan_config(u'ckanext.saml2auth.requested_authn_context', 'req1 req2')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path',
                         os.path.join(extras_folder, 'provider0', 'idp.xml'))
@pytest.mark.usefixtures(u'with_request_context')
def test_empty_comparison():
    with pytest.raises(ValueError) as e:
        saml2login()
        assert 'Unexpected comparison' in e


@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path',
                         os.path.join(extras_folder, 'provider0', 'idp.xml'))
@pytest.mark.usefixtures(u'with_request_context')
def test_saml2login_uses_sha256_sigalg():
    client = mock.Mock()
    client.prepare_for_authenticate.return_value = (
        'reqid',
        {u'headers': [(u'Location', u'https://idp.example.test/login')]}
    )

    with mock.patch('ckanext.saml2auth.views.saml2auth.h.saml_client', return_value=client):
        saml2login()

    client.prepare_for_authenticate.assert_called_once_with(
        relay_state='',
        sign=True,
        sigalg=SIG_RSA_SHA256
    )
