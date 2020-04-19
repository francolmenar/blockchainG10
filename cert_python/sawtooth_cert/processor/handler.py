# Copyright 2016-2018 Intel Corporation
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
# ------------------------------------------------------------------------------

import logging

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError

from cert_python.sawtooth_cert.processor.cert_payload import CertPayload
from cert_python.sawtooth_cert.processor.cert_state import Certificate
from cert_python.sawtooth_cert.processor.cert_state import CertState
from cert_python.sawtooth_cert.processor.cert_state import CERT_NAMESPACE

LOGGER = logging.getLogger(__name__)


class CertTransactionHandler(TransactionHandler):
    # Disable invalid-overridden-method. The sawtooth-sdk expects these to be
    # properties.
    # pylint: disable=invalid-overridden-method
    @property
    def family_name(self):
        return 'cert'

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [CERT_NAMESPACE]

    def apply(self, transaction, context):
        """
        Deconstruct the transaction and trigger the needed actions
        """

        header = transaction.header  # Set the header of the transaction
        signer = header.signer_public_key  # Set the Public Key of the Signer

        cert_payload = CertPayload.from_bytes(transaction.payload)  # Set the Payload from the transaction

        cert_state = CertState(context)  # Set the State of the transaction

        # Check the actions in the payload
        if cert_payload.action == 'delete':
            raise InvalidTransaction('Delete function not implemented')

        elif cert_payload.action == 'create':
            # Todo: probably change this
            if cert_state.get_certificate(cert_payload.identifier) is not None:
                raise InvalidTransaction(
                    'Invalid action: Certificate already exists: {}'.format(
                        cert_payload.identifier))

            certificate = Certificate(identifier=cert_payload.identifier,
                                      issuedName=cert_payload.issuedName,
                                      dateIssued=cert_payload.dateIssued,
                                      dateExpired=cert_payload.dateExpired,
                                      level=cert_payload.level,
                                      certificateName=cert_payload.certificateName,
                                      issuerName=cert_payload.issuerName)

            cert_state.set_certificate(cert_payload.identifier, certificate)
            _display("University {} signed a new certificate.".format(signer[:6]))

        elif cert_payload.action == 'edit':
            raise InvalidTransaction('Edit function not implemented')


def _display(msg):
    n = msg.count("\n")
    if n > 0:
        msg = msg.split("\n")
        length = max(len(line) for line in msg)
    else:
        length = len(msg)
        msg = [msg]

    LOGGER.debug("+" + (length + 2) * "-" + "+")
    for line in msg:
        LOGGER.debug("+ " + line.center(length) + " +")
    LOGGER.debug("+" + (length + 2) * "-" + "+")
