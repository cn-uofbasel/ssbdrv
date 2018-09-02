# Copyright (c) 2017 PySecretHandshake contributors (see AUTHORS for more details)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import hashlib

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from secret_handshake.crypto import SHSClientCrypto, SHSServerCrypto

APP_KEY = hashlib.sha256(b'app_key').digest()
SERVER_KEY_SEED = b'\xcaw\x01\xc2cQ\xfd\x94\x9f\x14\x84\x0c0<l\xd8\xe4\xf5>\x12\\\x96\xcd\x9b\x0c\x02z&\x96!\xe0\xa2'
CLIENT_KEY_SEED = b'\xbf\x02<\xd3e\x9d\xac-\xd1\x9e-{\xe5q\x90\x03\x11\xba\x8cSQ\xa0\xc3p~\x89\xe6\xeeb\xaa\x1c\x17'
SERVER_EPH_KEY_SEED = b"ed\x1c\x01\x03s\x04\xdc\x8e`\xd6Z\xd0u;\xcbX\x91\xd8ZO\xf8\xf0\xd6'\xd5\xb1Yy\x13yH"
CLIENT_EPH_KEY_SEED = b'u8\xd0\xe3\x85d_Pz\x0c\xf5\xfd\x15\xce2p#\xb0\xf0\x9f\xe6!\xe1\xcb\xf6\x93\t\xebr{1\x8b'


@pytest.fixture()
def server():
    server_key = SigningKey(SERVER_KEY_SEED)
    server_eph_key = PrivateKey(SERVER_EPH_KEY_SEED)
    return SHSServerCrypto(server_key, server_eph_key, application_key=APP_KEY)


@pytest.fixture()
def client():
    client_key = SigningKey(CLIENT_KEY_SEED)
    server_key = SigningKey(SERVER_KEY_SEED)
    client_eph_key = PrivateKey(CLIENT_EPH_KEY_SEED)
    return SHSClientCrypto(client_key, bytes(server_key.verify_key), client_eph_key, application_key=APP_KEY)


CLIENT_CHALLENGE = (b'd\xe8\xccD\xec\xb9E\xbb\xaa\xa7\x7f\xe38\x15\x16\xef\xca\xd22u\x1d\xfe<\xe7j'
                    b'\xd7\xf0uc\xf0r\xf3\x7f\t\x18\xec\x8c\xf7\xff\x8e\xa9\xc83\x13\x18R\x16\x1d'
                    b'\xe5\xc6K\xae\x94\xdbVt\x84\xdc\x1c@+D\x1c%')
CLIENT_AUTH = (b'\xf2\xaf?z\x15\x10\xd0\xf0\xdf\xe3\x91\xfe\x14\x1c}z\xab\xeey\xf5\xef\xfc\xa1EdV\xf2T\x95s[!$z'
               b'\xeb\x8f\x1b\x96JP\x17^\x92\xc8\x9e\xb4*5`\xf2\x8fI.\x93\xb9\x14:\xca@\x06\xff\xd1\xf1J\xc8t\xc4'
               b'\xd8\xc3$[\xc5\x94je\x83\x00%\x99\x10\x16\xb1\xa2\xb2\xb7\xbf\xc9\x88\x14\xb9\xbb^\tzq\xa4\xef\xc5'
               b'\xf5\x1f7#\xed\x92X\xb2\xe3\xe5\x8b[t3')
SERVER_CHALLENGE = (b'S\\\x06\x8d\xe5\xeb&*\xb8\x0bp\xb3Z\x8e\\\x85\x14\xaa\x1c\x8di\x9d\x7f\xa9\xeawl\xb9}\x85\xc3ik'
                    b'\x0c ($E\xb4\x8ax\xc4)t<\xd7\x8b\xd6\x07\xb7\xecw\x84\r\xe1-Iz`\xeb\x04\x89\xd6{')
SERVER_ACCEPT = (b'\xb4\xd0\xea\xfb\xfb\xf6s\xcc\x10\xc4\x99\x95"\x13 y\xa6\xea.G\xeed\x8d=t9\x88|\x94\xd1\xbcK\xd47'
                 b'\xd8\xbcG1h\xac\xd0\xeb*\x1f\x8d\xae\x0b\x91G\xa1\xe6\x96b\xf2\xda90u\xeb_\xab\xdb\xcb%d7}\xb5\xce'
                 b'(k\x15\xe3L\x9d)\xd5\xa1|:')
INTER_SHARED_SECRET = (b'vf\xd82\xaeU\xda]\x08\x9eZ\xd6\x06\xcc\xd3\x99\xfd\xce\xc5\x16e8n\x9a\x04\x04\x84\xc5\x1a'
                       b'\x8f\xf2M')
BOX_SECRET = b'\x03\xfe\xe3\x8c u\xbcl^\x17eD\x96\xa3\xa6\x880f\x11\x7f\x85\xf2:\xa3[`\x06[#l\xbcr'

SHARED_SECRET = b'UV\xad*\x8e\xce\x88\xf2\x87l\x13iZ\x12\xd7\xa6\xd1\x9c-\x9d\x07\xf5\xa96\x03w\x11\xe5\x96$m\x1d'
CLIENT_ENCRYPT_KEY = (b'\xec\x1f,\x82\x9f\xedA\xc0\xda\x87[\xf9u\xbf\xac\x9cI\xa5T\xd1\x91\xff\xa8.\xd0 \xfbU\xc7\x14'
                      b')\xc7')
CLIENT_DECRYPT_KEY = b'\xf9e\xa0As\xb2=\xb7P~\xf3\xf9(\xfd\x7f\xfe\xb7TZhn\xd7\x8c=\xea.o\x9e\x8c9)\x10'
CLIENT_ENCRYPT_NONCE = b'S\\\x06\x8d\xe5\xeb&*\xb8\x0bp\xb3Z\x8e\\\x85\x14\xaa\x1c\x8di\x9d\x7f\xa9'
CLIENT_DECRYPT_NONCE = b'd\xe8\xccD\xec\xb9E\xbb\xaa\xa7\x7f\xe38\x15\x16\xef\xca\xd22u\x1d\xfe<\xe7'


def test_handshake(client, server):
    client_challenge = client.generate_challenge()
    assert client_challenge == CLIENT_CHALLENGE
    assert server.verify_challenge(client_challenge)

    server_challenge = server.generate_challenge()
    assert server_challenge == SERVER_CHALLENGE
    assert client.verify_server_challenge(server_challenge)

    assert client.shared_secret == INTER_SHARED_SECRET

    client_auth = client.generate_client_auth()
    assert client_auth == CLIENT_AUTH
    assert server.verify_client_auth(client_auth)

    assert server.shared_secret == client.shared_secret

    server_accept = server.generate_accept()
    assert server_accept == SERVER_ACCEPT
    assert client.verify_server_accept(server_accept)

    assert client.box_secret == BOX_SECRET
    assert client.box_secret == server.box_secret

    client_keys = client.get_box_keys()
    server_keys = server.get_box_keys()

    assert client_keys['shared_secret'] == SHARED_SECRET
    assert client_keys['encrypt_key'] == CLIENT_ENCRYPT_KEY
    assert client_keys['decrypt_key'] == CLIENT_DECRYPT_KEY
    assert client_keys['encrypt_nonce'] == CLIENT_ENCRYPT_NONCE
    assert client_keys['decrypt_nonce'] == CLIENT_DECRYPT_NONCE

    assert client_keys['shared_secret'] == server_keys['shared_secret']
    assert client_keys['encrypt_key'] == server_keys['decrypt_key']
    assert client_keys['encrypt_nonce'] == server_keys['decrypt_nonce']
