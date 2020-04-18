# Copyright 2017 Intel Corporation
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

from __future__ import print_function

import argparse
import getpass
import logging
import os
import traceback
import sys
import pkg_resources

from colorlog import ColoredFormatter

from examples.cert_python.sawtooth_cert.cert_client import CertClient
from examples.cert_python.sawtooth_cert.cert_exceptions import CertException


DISTRIBUTION_NAME = 'sawtooth-cert'


DEFAULT_URL = 'http://127.0.0.1:8008'


def create_console_handler(verbose_level):
    """
    Create console
    """
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)

    if verbose_level == 0:
        clog.setLevel(logging.WARN)
    elif verbose_level == 1:
        clog.setLevel(logging.INFO)
    else:
        clog.setLevel(logging.DEBUG)

    return clog


def setup_loggers(verbose_level):
    """
    Logers ???
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))


def add_create_parser(subparsers, parent_parser):
    """
    Add parser for create
    """
    parser = subparsers.add_parser(
        'create',
        help='Creates a new certificate',
        description='Sends a transaction to start an cert game with the '
        'identifier <name>. This transaction will fail if the specified '
        'game already exists.',
        parents=[parent_parser])

    parser.add_argument(
        'identifier',
        type=str,
        help='unique identifier for the new certificate')

    parser.add_argument(
        'certificate',
        type=str,
        help='certificate json data, b64 encoded')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_list_parser(subparsers, parent_parser):
    """
    Add Parser for List
    """
    parser = subparsers.add_parser(
        'list',
        help='Displays information for all certificates',
        description='Displays information for all certificates in state.',
        parents=[parent_parser])

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')


def add_show_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'show',
        help='Displays information about a certificate',
        description='Displays the certificate <identifier>',
        parents=[parent_parser])

    parser.add_argument(
        'identifier',
        type=str,
        help='unique identifier for the new certificate')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')


def add_take_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'edit',
        help='Edit a certificate',
        description='Sends a transaction to edit a certificate',
        parents=[parent_parser])

    parser.add_argument(
        'identifier',
        type=str,
        help='unique identifier for the new certificate')

    parser.add_argument(
        'certificate',
        type=str,
        help='certificate json data, b64 encoded')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for take transaction '
        'to commit')


def add_delete_parser(subparsers, parent_parser):
    parser = subparsers.add_parser('delete', parents=[parent_parser])

    parser.add_argument(
        'identifier',
        type=str,
        help='unique identifier for the new certificate')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for delete transaction to commit')


def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument(
        '-v', '--verbose',
        action='count',
        help='enable more verbose output')

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to send Cert transactions.',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    subparsers.required = True

    add_create_parser(subparsers, parent_parser)
    add_list_parser(subparsers, parent_parser)
    add_show_parser(subparsers, parent_parser)
    add_take_parser(subparsers, parent_parser)
    add_delete_parser(subparsers, parent_parser)

    return parser


def do_list(args):
    """
    Coordinate the calls for List
    """
    url = _get_url(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CertClient(base_url=url, keyfile=None)

    certificate_list = [
        certificate.split(',')
        for certificates in client.list(auth_user=auth_user,
                                 auth_password=auth_password)
        for certificate in certificates.decode().split('|')
    ]

    if certificate_list is not None:
        fmt = "%-15s %-15.15s %-15.15s %-9s %s"
        print(fmt % ('GAME', 'PLAYER 1', 'PLAYER 2', 'BOARD', 'STATE'))
        for certificate in certificate_list:
            print(certificate)
    else:
        raise CertException("Could not retrieve game listing.")


def do_show(args):
    """
    Coordinate the calls for Show
    """
    identifier = args.identifier

    url = _get_url(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CertClient(base_url=url, keyfile=None)

    data = client.show(identifier, auth_user=auth_user, auth_password=auth_password)

    if data is not None:
        # Todo: improve this print
        print(data)

    else:
        raise CertException("Game not found: {}".format(identifier))


def do_create(args):
    identifier = args.identifier
    certificate = args.certificate

    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CertClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.create(
            identifier, certificate, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.create(
            identifier, certificate, auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))


def do_edit(args):
    identifier = args.identifier
    certificate = args.certificate

    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CertClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.take(
            identifier, certificate, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.take(
            identifier, certificate,
            auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))


def do_delete(args):
    identifier = args.identifier

    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CertClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.delete(
            identifier, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.delete(
            identifier, auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))


def _get_url(args):
    return DEFAULT_URL if args.url is None else args.url


def _get_keyfile(args):
    username = getpass.getuser() if args.username is None else args.username
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")

    return '{}/{}.priv'.format(key_dir, username)


def _get_auth_info(args):
    auth_user = args.auth_user
    auth_password = args.auth_password
    if auth_user is not None and auth_password is None:
        auth_password = getpass.getpass(prompt="Auth Password: ")

    return auth_user, auth_password


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)

    if args.verbose is None:
        verbose_level = 0
    else:
        verbose_level = args.verbose

    setup_loggers(verbose_level=verbose_level)

    if args.command == 'create':
        do_create(args)
    elif args.command == 'list':
        do_list(args)
    elif args.command == 'show':
        do_show(args)
    elif args.command == 'edit':
        do_edit(args)
    elif args.command == 'delete':
        do_delete(args)
    else:
        raise CertException("invalid command: {}".format(args.command))


def main_wrapper():
    try:
        main()
    except CertException as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
