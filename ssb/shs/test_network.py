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

import os
from asyncio import Event, wait_for

import pytest
from nacl.signing import SigningKey

from secret_handshake.util import AsyncBuffer


class DummyCrypto(object):
    """Dummy crypto module, pretends everything is fine."""
    def verify_server_challenge(self, data):
        return True

    def verify_challenge(self, data):
        return True

    def verify_server_accept(self, data):
        return True

    def generate_challenge(self):
        return b'CHALLENGE'

    def generate_client_auth(self):
        return b'AUTH'

    def verify_client_auth(self, data):
        return True

    def generate_accept(self):
        return b'ACCEPT'

    def get_box_keys(self):
        return {
            'encrypt_key': b'x' * 32,
            'encrypt_nonce': b'x' * 32,
            'decrypt_key': b'x' * 32,
            'decrypt_nonce': b'x' * 32
        }

    def clean(self):
        return


def _dummy_boxstream(stream, **kwargs):
    """Identity boxstream, no tansformation."""
    return stream


def _client_stream_mocker():
    reader = AsyncBuffer(b'xxx')
    writer = AsyncBuffer(b'xxx')

    async def _create_mock_streams(host, port):
        return reader, writer

    return reader, writer, _create_mock_streams


def _server_stream_mocker():
    reader = AsyncBuffer(b'xxx')
    writer = AsyncBuffer(b'xxx')

    async def _create_mock_server(cb, host, port):
        await cb(reader, writer)

    return reader, writer, _create_mock_server


@pytest.mark.asyncio
async def test_client(mocker):
    reader, writer, _create_mock_streams = _client_stream_mocker()
    mocker.patch('asyncio.open_connection', new=_create_mock_streams)
    mocker.patch('secret_handshake.boxstream.BoxStream', new=_dummy_boxstream)
    mocker.patch('secret_handshake.boxstream.UnboxStream', new=_dummy_boxstream)

    from secret_handshake import SHSClient

    client = SHSClient('shop.local', 1111, SigningKey.generate(), os.urandom(32))
    client.crypto = DummyCrypto()

    await client.open()
    reader.append(b'TEST')
    assert (await client.read()) == b'TEST'
    client.disconnect()


@pytest.mark.asyncio
async def test_server(mocker):
    from secret_handshake import SHSServer

    resolve = Event()

    async def _on_connect(conn):
        server.disconnect()
        resolve.set()

    reader, writer, _create_mock_server = _server_stream_mocker()
    mocker.patch('asyncio.start_server', new=_create_mock_server)
    mocker.patch('secret_handshake.boxstream.BoxStream', new=_dummy_boxstream)
    mocker.patch('secret_handshake.boxstream.UnboxStream', new=_dummy_boxstream)

    server = SHSServer('shop.local', 1111, SigningKey.generate(), os.urandom(32))
    server.crypto = DummyCrypto()

    server.on_connect(_on_connect)

    await server.listen()
    await wait_for(resolve.wait(), 5)
