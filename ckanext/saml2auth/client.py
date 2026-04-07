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
import logging
import xml.etree.ElementTree as ET

from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2.client import Saml2Client as Pysaml2Client
from saml2.response import UnsolicitedResponse
from saml2.sigver import SigverError
from saml2.sigver import SignatureError

from ckanext.saml2auth.spconfig import get_config as sp_config

log = logging.getLogger(__name__)

DS_NS = 'http://www.w3.org/2000/09/xmldsig#'
XENC_NS = 'http://www.w3.org/2001/04/xmlenc#'


def strip_embedded_encryption_certificates(xml_text):
    if not xml_text:
        return xml_text

    if isinstance(xml_text, bytes):
        xml_text = xml_text.decode('utf-8')

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return xml_text

    encrypted_key_path = './/{{{}}}EncryptedKey'.format(XENC_NS)
    x509_data_tag = '{{{}}}X509Data'.format(DS_NS)
    removed = False

    for encrypted_key in root.findall(encrypted_key_path):
        for key_info in encrypted_key.findall('./{{{}}}KeyInfo'.format(DS_NS)):
            for child in list(key_info):
                if child.tag == x509_data_tag:
                    key_info.remove(child)
                    removed = True

    if not removed:
        return xml_text

    return ET.tostring(root, encoding='unicode')


class Saml2Client(Pysaml2Client):

    @staticmethod
    def _wrap_decrypt_keys(response):
        original_decrypt_keys = response.sec.decrypt_keys

        def decrypt_keys_with_fallback(enctext, keys=None):
            try:
                return original_decrypt_keys(enctext, keys)
            except Exception as exc:
                sanitized = strip_embedded_encryption_certificates(enctext)
                if sanitized == enctext:
                    raise

                log.warning(
                    'Retrying SAML decryption without embedded encryption certificate: %s',
                    exc,
                )
                return original_decrypt_keys(sanitized, keys)

        response.sec.decrypt_keys = decrypt_keys_with_fallback
        return response

    def _parse_response(
        self,
        xmlstr,
        response_cls,
        service,
        binding,
        outstanding_certs=None,
        **kwargs
    ):
        if self.config.accepted_time_diff:
            kwargs['timeslack'] = self.config.accepted_time_diff

        if 'asynchop' not in kwargs:
            kwargs['asynchop'] = binding not in [BINDING_SOAP, BINDING_PAOS]

        response = None
        if not xmlstr:
            return response

        if 'return_addrs' not in kwargs:
            bindings = {
                BINDING_SOAP,
                BINDING_HTTP_REDIRECT,
                BINDING_HTTP_POST,
            }
            if binding in bindings:
                kwargs['return_addrs'] = self.config.endpoint(
                    service,
                    binding=binding,
                    context=self.entity_type,
                )

        try:
            response = response_cls(self.sec, **kwargs)
        except Exception as exc:
            log.info('%s', exc)
            raise

        xmlstr = self.unravel(xmlstr, binding, response_cls.msgtype)
        if not xmlstr:
            return None

        try:
            response_is_signed = False
            require_response_signature = response.require_response_signature
            response.require_response_signature = True
            response = response.loads(xmlstr, False, origxml=xmlstr)
        except SigverError as err:
            if require_response_signature:
                log.error('Signature Error: %s', err)
                raise

            response.require_response_signature = require_response_signature
            response = response.loads(xmlstr, False, origxml=xmlstr)
        except UnsolicitedResponse:
            log.error('Unsolicited response')
            raise
        except Exception as err:
            if 'not well-formed' in '%s' % err:
                log.error('Not well-formed XML')
            raise
        else:
            response_is_signed = True
        finally:
            response.require_response_signature = require_response_signature

        log.debug('XMLSTR: %s', xmlstr)

        if not response:
            return response

        response = self._wrap_decrypt_keys(response)

        keys = None
        if outstanding_certs:
            try:
                cert = outstanding_certs[response.in_response_to]
            except KeyError:
                keys = None
            else:
                if not isinstance(cert, list):
                    cert = [cert]
                keys = []
                for _cert in cert:
                    keys.append(_cert['key'])

        try:
            assertions_are_signed = False
            require_signature = response.require_signature
            response.require_signature = True
            response.verify(keys)
        except SignatureError as err:
            if require_signature:
                log.error('Signature Error: %s', err)
                raise

            response.require_signature = require_signature
            response.verify(keys)
        else:
            assertions_are_signed = True
        finally:
            response.require_signature = require_signature

        if response.require_signature_or_response_signature:
            if not response_is_signed and not assertions_are_signed:
                msg = 'Neither the response nor the assertions are signed'
                log.error(msg)
                raise SigverError(msg)

        return response

    def do_logout(self, *args, **kwargs):
        if not kwargs.get('expected_binding'):
            try:
                kwargs['expected_binding'] = sp_config()[u'logout_expected_binding']
            except AttributeError:
                log.warning(
                    'ckanext.saml2auth.logout_expected_binding'
                    'is not defined. Default binding will be used.'
                )
        return super().do_logout(*args, **kwargs)
