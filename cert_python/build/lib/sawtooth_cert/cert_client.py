# Copyright 2016 Intel Corporation
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

import hashlib
import base64
from base64 import b64encode
import time
import random
import requests
import yaml

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch

from examples.cert_python.sawtooth_cert.cert_exceptions import CertException


def _sha512(data):
    return hashlib.sha512(data).hexdigest()


class CertClient:
    """
    Data Structure for a Client
    """

    def __init__(self, base_url, keyfile=None):
        """
        Set the URL, handles the Private Key and Set the Signer
        """

        self._base_url = base_url  # Set the URL

        if keyfile is None:  # Check if there is no Signer
            self._signer = None  # Set the Signer to None
            return

        try:  # Open the private key from a file
            with open(keyfile) as fd:
                private_key_str = fd.read().strip()  # Read the Private Key as a String
        except OSError as err:
            raise CertException(
                'Failed to read private key {}: {}'.format(
                    keyfile, str(err)))

        try:  # Convert the Private Key from String to Object
            private_key = Secp256k1PrivateKey.from_hex(private_key_str)
        except ParseError as e:
            raise CertException(
                'Unable to load private key: {}'.format(str(e)))

        self._signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_key)  # Set the signer using the Private Key

    def create(self, identifier, certificate="e30=", wait=None, auth_user=None, auth_password=None):
        """
        Set the arguments for calling _send_cert_txn for Create
        """
        return self._send_cert_txn(
            identifier=identifier,
            action="create",
            certificate=certificate,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def delete(self, identifier, certificate="e30=", wait=None, auth_user=None, auth_password=None):
        """
        Set the arguments for calling _send_cert_txn for Delete
        """
        return self._send_cert_txn(
            identifier,
            "delete",
            certificate=certificate,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def edit(self, identifier, certificate="e30=", wait=None, auth_user=None, auth_password=None):
        """
        Set the arguments for calling _send_cert_txn for Take
        """
        return self._send_cert_txn(
            identifier,
            "edit",
            certificate=certificate,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def list(self, auth_user=None, auth_password=None):
        """
        I'm not sure what it's happening, Some request is sent
        """
        cert_prefix = self._get_prefix()  # Get the Cert Prefix, Not sure if we need it for us

        result = self._send_request(
            "state?address={}".format(cert_prefix),
            auth_user=auth_user,
            auth_password=auth_password)  # Send the Request

        try:
            encoded_entries = yaml.safe_load(result)["data"]

            return [
                base64.b64decode(entry["data"]) for entry in encoded_entries
            ]

        except BaseException:
            return None

    def show(self, identifier, auth_user=None, auth_password=None):
        """
        I'm not sure what it's happening, Some request is sent
        """
        address = self._get_address(identifier)  # Get the Address

        result = self._send_request(
            "state/{}".format(address),
            identifier=identifier,
            auth_user=auth_user,
            auth_password=auth_password)  # Send the request
        try:
            return base64.b64decode(yaml.safe_load(result)["data"])

        except BaseException:
            return None

    def _get_status(self, batch_id, wait, auth_user=None, auth_password=None):
        """
        I'm not sure what it's happening, Some request is sent
        """
        try:
            result = self._send_request(
                'batch_statuses?id={}&wait={}'.format(batch_id, wait),  # That URL could be set as a constant
                auth_user=auth_user,
                auth_password=auth_password)  # Send a request
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise CertException(err)

    @staticmethod
    def _get_prefix():
        """
        Get the prefix?????????
        """
        return _sha512('cert'.encode('utf-8'))[0:6]

    def _get_address(self, identifier):
        """
        Get the total address:     Prefix + Game Addr
        """
        cert_prefix = self._get_prefix()
        certificate_address = _sha512(identifier.encode('utf-8'))[0:64]
        return cert_prefix + certificate_address

    def _send_request(self, suffix, data=None, content_type=None, identifier=None, auth_user=None, auth_password=None):
        """
        Send the request
        """
        if self._base_url.startswith("http://"):  # Set the URL
            url = "{}/{}".format(self._base_url, suffix)
        else:
            url = "http://{}/{}".format(self._base_url, suffix)

        headers = {}
        if auth_user is not None:  # No Authenticated User in the Header
            auth_string = "{}:{}".format(auth_user, auth_password)
            b64_string = b64encode(auth_string.encode()).decode()
            auth_header = 'Basic {}'.format(b64_string)
            headers['Authorization'] = auth_header

        if content_type is not None:  # Content Type ????
            headers['Content-Type'] = content_type

        try:  # Send the request
            if data is not None:  # Check if there is no data, call Post
                result = requests.post(url, headers=headers, data=data)
            else:  # There is data, call Get
                result = requests.get(url, headers=headers)

            if result.status_code == 404:  # Check the Result Status Code
                raise CertException("No such certificate: {}".format(identifier))

            if not result.ok:
                raise CertException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise CertException(
                'Failed to connect to {}: {}'.format(url, str(err)))

        except BaseException as err:
            raise CertException(err)

        return result.text

    def _send_cert_txn(self, identifier, action, certificate, wait=None, auth_user=None, auth_password=None):
        # Serialization is just a delimited utf-8 encoded string
        payload = ",".join([action, identifier, str(certificate)]).encode()

        # Construct the address
        address = self._get_address(identifier)

        # Construct the Header
        header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name="cert",
            family_version="1.0",
            inputs=[address],
            outputs=[address],
            dependencies=[],
            payload_sha512=_sha512(payload),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            nonce=hex(random.randint(0, 2 ** 64))
        ).SerializeToString()

        # Set the signature, Signing the header of the transaction
        signature = self._signer.sign(header)

        # Set the Transaction, with the Header, Payload and Signature
        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=signature
        )
        # Create the list of Batches
        batch_list = self._create_batch_list([transaction])
        # Set the id of the Batch to the sign of the first transaction
        batch_id = batch_list.batches[0].header_signature

        if wait and wait > 0:  # ???????
            wait_time = 0
            start_time = time.time()
            response = self._send_request(
                "batches", batch_list.SerializeToString(),
                'application/octet-stream',
                auth_user=auth_user,
                auth_password=auth_password)  # Send the Request for the list of batches
            while wait_time < wait:  # ???????
                status = self._get_status(
                    batch_id,
                    wait - int(wait_time),
                    auth_user=auth_user,
                    auth_password=auth_password)  # Get the status of the request
                wait_time = time.time() - start_time

                if status != 'PENDING':  # Check if there is a response
                    return response

            return response

        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
            auth_user=auth_user,
            auth_password=auth_password)  # Send the request, I HAVE NO IDEA WHY HERE

    def _create_batch_list(self, transactions):
        """
        Create a list of Batches with transactions
        """
        # List of signatures of all the transactions
        transaction_signatures = [t.header_signature for t in transactions]

        # Header of the Batch - Signer PK, List of signatures -
        header = BatchHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            transaction_ids=transaction_signatures
        ).SerializeToString()

        # Signature is the sign of the header
        signature = self._signer.sign(header)

        # Create the Batch
        batch = Batch(
            header=header,
            transactions=transactions,
            header_signature=signature)
        return BatchList(batches=[batch])  # Return the batch as an Array
