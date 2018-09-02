# ssb/shs/network.py

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


import asyncio

from async_generator import async_generator, yield_

from .boxstream import get_stream_pair
from .crypto import SHSClientCrypto, SHSServerCrypto


class SHSClientException(Exception):
    pass


class SHSDuplexStream(object):
    def __init__(self):
        self.write_stream = None
        self.read_stream = None
        self.is_connected = False

    def write(self, data):
        self.write_stream.write(data)

    async def read(self):
        return await self.read_stream.read()

    def close(self):
        self.write_stream.close()
        self.read_stream.close()
        self.is_connected = False

    @async_generator
    async def __aiter__(self):
        async for msg in self.read_stream:
            await yield_(msg)


class SHSEndpoint(object):
    def __init__(self):
        self._on_connect = None
        self.crypto = None

    def on_connect(self, cb):
        self._on_connect = cb

    def disconnect(self):
        raise NotImplementedError


class SHSServer(SHSEndpoint):
    def __init__(self, host, port, server_kp, application_key=None, sess=None):
        super(SHSServer, self).__init__()
        self.host = host
        self.port = port
        self.sess = sess
        self.crypto = SHSServerCrypto(server_kp, application_key=application_key)
        self.connections = []

    async def _handshake(self, reader, writer):
        data = await reader.readexactly(64)
        if not self.crypto.verify_challenge(data):
            raise SHSClientException('Client challenge is not valid')

        writer.write(self.crypto.generate_challenge())

        data = await reader.readexactly(112)
        if not self.crypto.verify_client_auth(data):
            raise SHSClientException('Client auth is not valid')

        writer.write(self.crypto.generate_accept())

    async def handle_connection(self, reader, writer):
        self.crypto.clean()
        await self._handshake(reader, writer)
        keys = self.crypto.get_box_keys()
        self.crypto.clean()

        conn = SHSServerConnection.from_byte_streams(reader, writer, **keys)
        self.connections.append(conn)

        if self._on_connect:
            asyncio.ensure_future(self._on_connect(conn, self.sess))

    async def listen(self):
        await asyncio.start_server(self.handle_connection, self.host, self.port)

    def disconnect(self):
        for connection in self.connections:
            connection.close()


class SHSServerConnection(SHSDuplexStream):
    def __init__(self, read_stream, write_stream):
        super(SHSServerConnection, self).__init__()
        self.read_stream = read_stream
        self.write_stream = write_stream

    @classmethod
    def from_byte_streams(cls, reader, writer, **keys):
        reader, writer = get_stream_pair(reader, writer, **keys)
        return cls(reader, writer)


class SHSClient(SHSDuplexStream, SHSEndpoint):
    def __init__(self, host, port, client_kp, server_pub_key, ephemeral_key=None, application_key=None):
        SHSDuplexStream.__init__(self)
        SHSEndpoint.__init__(self)
        self.host = host
        self.port = port
        self.crypto = SHSClientCrypto(client_kp, server_pub_key, ephemeral_key=ephemeral_key,
                                      application_key=application_key)

    async def _handshake(self, reader, writer):
        writer.write(self.crypto.generate_challenge())

        data = await reader.readexactly(64)
        if not self.crypto.verify_server_challenge(data):
            raise SHSClientException('Server challenge is not valid')

        writer.write(self.crypto.generate_client_auth())

        data = await reader.readexactly(80)
        if not self.crypto.verify_server_accept(data):
            raise SHSClientException('Server accept is not valid')

    async def open(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        await self._handshake(reader, writer)

        keys = self.crypto.get_box_keys()
        self.crypto.clean()

        self.read_stream, self.write_stream = get_stream_pair(reader, writer, **keys)
        self.writer = writer
        self.is_connected = True
        if self._on_connect:
            await self._on_connect()

    def disconnect(self):
        self.close()
