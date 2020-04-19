# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------

from sawtooth_sdk.processor.exceptions import InvalidTransaction
import json
import base64

CERT_FIELDS = ['issuedName', 'dateIssued', 'dateExpired', 'level', 'certificateName', 'issuerName']


class CertPayload:
    """
    Object defining the Structure of the Payload
    """

    def __init__(self, payload):
        try:
            # The payload is csv utf-8 encoded string
            # Separate the original String command into the variables to create the PayLoad
            action, identifier, certificate_encoded = payload.decode().split(",")
        except ValueError:
            raise InvalidTransaction("Invalid payload serialization")

        certificate_values = dict()
        json_certificate = None

        # Check for errors in the variables
        if not identifier:
            raise InvalidTransaction('Identifier is required')

        if not action:
            raise InvalidTransaction('Action is required')

        if action not in ('create', 'edit', 'delete'):
            raise InvalidTransaction('Invalid action: {}'.format(action))

        if action != 'create':
            raise InvalidTransaction('Only create action is supported')

        if action == 'create':
            # If action create check that the certificate is valid
            try:
                json_certificate = json.loads(base64.b64decode(certificate_encoded))
            except json.JSONDecodeError:
                raise InvalidTransaction('Certificate not valid')

            # Check that it has every field
            for key in CERT_FIELDS:
                if json_certificate.get(key) is None:
                    raise InvalidTransaction('Certificate not valid')

        if json_certificate:
            for key in CERT_FIELDS:
                certificate_values[key] = json_certificate.get(key)

        # Store the values into the variables of the PayLoad object
        self._identifier = identifier
        self._action = action
        self._issuedName = certificate_values.get('issuedName', '')
        self._dateIssued = certificate_values.get('dateIssued', '')
        self._dateExpired = certificate_values.get('dateExpired', '')
        self._level = certificate_values.get('level', '')
        self._certificateName = certificate_values.get('certificateName', '')
        self._issuerName = certificate_values.get('issuerName', '')

    @staticmethod
    def from_bytes(payload):
        return CertPayload(payload=payload)

    @property
    def identifier(self):
        return self._identifier

    @property
    def action(self):
        return self._action

    @property
    def issuedName(self):
        return self._issuedName

    @property
    def dateIssued(self):
        return self._dateIssued

    @property
    def dateExpired(self):
        return self._dateExpired

    @property
    def level(self):
        return self._level

    @property
    def certificateName(self):
        return self._certificateName

    @property
    def issuerName(self):
        return self._issuerName

