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

import hashlib

from sawtooth_sdk.processor.exceptions import InternalError

CERT_NAMESPACE = hashlib.sha512('cert'.encode("utf-8")).hexdigest()[0:6]


def _make_cert_address(identifier):
    """
    Create the specific Address for the Certificate - It can be reused -
    """
    return CERT_NAMESPACE + hashlib.sha512(identifier.encode('utf-8')).hexdigest()[:64]


class Certificate:
    """
    Data Structure that holds the data for the Game Status
    """
    def __init__(self, identifier, issuedName, dateIssued, dateExpired, level, certificateName, issuerName):
        self.identifier = identifier
        self.issuedName = issuedName
        self.dateIssued = dateIssued
        self.dateExpired = dateExpired
        self.level = level
        self.certificateName = certificateName
        self.issuerName = issuerName


class CertState:
    """
    State which holds a context

    Manages the actions regarding the Certificate State
        - Delete
        - Set
        - Get
        - Store
        - Load
        - Deserialize the bytes into Python Objects
        - Serialize Python Objects into bytes
    """
    TIMEOUT = 3

    def __init__(self, context):
        """Constructor.

        Args:
            context (sawtooth_sdk.processor.context.Context): Access to
                validator state from within the transaction processor.
        """

        self._context = context
        self._address_cache = {}

    def delete_certificate(self, identifier):
        """Delete the certificate named game_name from state.

        Args:
            identifier (str): The certificate identifier.

        Raises:
            KeyError: The Game with game_name does not exist.
        """
        raise NotImplemented('Delete certificate not implemented yet')

    def set_certificate(self, identifier, certificate):
        """Store the certificate in the validator state.

        Args:
            identifier (str): The identifier.
            certificate (Certificate): The information specifying the current certificate.
        """

        certificates = self._load_certificates(identifier=identifier)

        certificates[identifier] = certificate

        self._store_certificate(identifier, certificates=certificates)

    def get_certificate(self, identifier):
        """Get the certificate associated with issuedName.

        Args:
            identifier (str): The identifier.

        Returns:
            (Certificate): All the information specifying a certificate.
        """

        return self._load_certificates(identifier=identifier).get(identifier)

    def _store_certificate(self, identifier, certificates):
        address = _make_cert_address(identifier)

        state_data = self._serialize(certificates)

        self._address_cache[address] = state_data

        self._context.set_state(
            {address: state_data},
            timeout=self.TIMEOUT)

    def _delete_certificate(self, identifier):
        address = _make_cert_address(identifier)

        self._context.delete_state(
            [address],
            timeout=self.TIMEOUT)

        self._address_cache[address] = None

    def _load_certificates(self, identifier):
        address = _make_cert_address(identifier)

        if address in self._address_cache:
            if self._address_cache[address]:
                serialized_certificates = self._address_cache[address]
                certificates = self._deserialize(serialized_certificates)
            else:
                certificates = {}
        else:
            state_entries = self._context.get_state(
                [address],
                timeout=self.TIMEOUT)
            if state_entries:

                self._address_cache[address] = state_entries[0].data

                certificates = self._deserialize(data=state_entries[0].data)

            else:
                self._address_cache[address] = None
                certificates = {}

        return certificates

    @staticmethod
    def _deserialize(data):
        """Take bytes stored in state and deserialize them into Python
        Game objects.

        Args:
            data (bytes): The UTF-8 encoded string stored in state.

        Returns:
            (dict): certificate name (str) keys, Game values.
        """

        certificates = {}
        try:
            for certificate in data.decode().split("|"):
                identifier, issuedName, dateIssued, dateExpired, level, certificateName, issuerName = certificate.split(",")

                certificates[identifier] = Certificate(identifier, issuedName, dateIssued, dateExpired, level, certificateName, issuerName)
        except ValueError:
            raise InternalError("Failed to deserialize certificate data")

        return certificates

    @staticmethod
    def _serialize(certificates):
        """Takes a dict of game objects and serializes them into bytes.

        Args:
            certificates (dict): certificate

        Returns:
            (bytes): The UTF-8 encoded string stored in state.
        """

        certificate_strs = []
        for identifier, c in certificates.items():
            certificate_str = ",".join(
                [identifier, c.issuedName, c.dateIssued, c.dateExpired, c.level, c.certificateName, c.issuerName])
            certificate_strs.append(certificate_str)

        return "|".join(sorted(certificate_strs)).encode()
