# ssb/shs/boxtream.py

# June 2017  (c) Pedro Ferreira <pedro@dete.st>
#            https://github.com/pferreir/pyssb

import struct
from asyncio import IncompleteReadError

from async_generator import async_generator, yield_
from nacl.secret import SecretBox

from .util import inc_nonce, split_chunks

HEADER_LENGTH = 2 + 16 + 16
MAX_SEGMENT_SIZE = 4 * 1024
TERMINATION_HEADER = (b'\x00' * 18)


def get_stream_pair(reader, writer, **kwargs):
    """Return a tuple with `(unbox_stream, box_stream)` (reader/writer).

    :return: (:class:`secret_handshake.boxstream.UnboxStream`,
              :class:`secret_handshake.boxstream.BoxStream`) """
    box_args = {
        'key': kwargs['encrypt_key'],
        'nonce': kwargs['encrypt_nonce'],
    }
    unbox_args = {
        'key': kwargs['decrypt_key'],
        'nonce': kwargs['decrypt_nonce'],
    }
    return UnboxStream(reader, **unbox_args), BoxStream(writer, **box_args)


class UnboxStream(object):
    def __init__(self, reader, key, nonce):
        self.reader = reader
        self.key = key
        self.nonce = nonce
        self.closed = False

    async def read(self):
        try:
            data = await self.reader.readexactly(HEADER_LENGTH)
        except IncompleteReadError:
            self.closed = True
            return None

        box = SecretBox(self.key)

        header = box.decrypt(data, self.nonce)

        if header == TERMINATION_HEADER:
            self.closed = True
            return None

        length = struct.unpack('>H', header[:2])[0]
        mac = header[2:]

        data = await self.reader.readexactly(length)

        body = box.decrypt(mac + data, inc_nonce(self.nonce))

        self.nonce = inc_nonce(inc_nonce(self.nonce))
        return body

    @async_generator
    async def __aiter__(self):
        while True:
            data = await self.read()
            if data is None:
                return
            await yield_(data)


class BoxStream(object):
    def __init__(self, writer, key, nonce):
        self.writer = writer
        self.key = key
        self.box = SecretBox(self.key)
        self.nonce = nonce

    def write(self, data):
        for chunk in split_chunks(data, MAX_SEGMENT_SIZE):
            body = self.box.encrypt(chunk, inc_nonce(self.nonce))[24:]
            header = struct.pack('>H', len(body) - 16) + body[:16]

            hdrbox = self.box.encrypt(header, self.nonce)[24:]
            self.writer.write(hdrbox)

            self.nonce = inc_nonce(inc_nonce(self.nonce))
            self.writer.write(body[16:])

    def close(self):
        self.writer.write(self.box.encrypt(b'\x00' * 18, self.nonce)[24:])
