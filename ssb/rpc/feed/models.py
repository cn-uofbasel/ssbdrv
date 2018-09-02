# ssb/rpc/feed/models.py

# June 2017  (c) Pedro Ferreira <pedro@dete.st>
#            https://github.com/pferreir/pyssb

import datetime
from base64 import b64encode
from collections import namedtuple, OrderedDict
from hashlib import sha256

from json import dumps, loads


OrderedMsg = namedtuple('OrderedMsg', ('previous', 'author', 'sequence', 'timestamp', 'hash', 'content'))


class NoPrivateKeyException(Exception):
    pass


def to_ordered(data):
    smsg = OrderedMsg(**data)
    return OrderedDict((k, getattr(smsg, k)) for k in smsg._fields)


def get_millis_1970():
    return int(datetime.datetime.utcnow().timestamp() * 1000)


class Feed(object):
    def __init__(self, public_key):
        self.public_key = public_key

    @property
    def id(self):
        return (b'@' + b64encode(bytes(self.public_key)) + \
                b'.ed25519').decode('ascii')

    def sign(self, msg):
        raise NoPrivateKeyException('Cannot use remote identity to sign (no private key!)')


class LocalFeed(Feed):
    def __init__(self, private_key):
        self.private_key = private_key

    @property
    def public_key(self):
        return self.private_key.verify_key

    def sign(self, msg):
        return self.private_key.sign(msg).signature


class Message(object):
    def __init__(self, feed, content, signature, sequence=1, timestamp=None, previous=None):
        self.feed = feed
        self.content = content

        if signature is None:
            raise ValueError("signature can't be None")
        self.signature = signature

        self.previous = previous
        if self.previous:
            self.sequence = self.previous.sequence + 1
        else:
            self.sequence = sequence

        self.timestamp = get_millis_1970() if timestamp is None else timestamp

    @classmethod
    def parse(cls, data, feed):
        obj = loads(data, object_pairs_hook=OrderedDict)
        msg = cls(feed, obj['content'], timestamp=obj['timestamp'])
        return msg

    def serialize(self, add_signature=True):
        return dumps(self.to_dict(add_signature=add_signature), indent=2).encode('utf-8')

    def to_dict(self, add_signature=True):
        obj = to_ordered({
            'previous': self.previous.key if self.previous else None,
            'author': self.feed.id,
            'sequence': self.sequence,
            'timestamp': self.timestamp,
            'hash': 'sha256',
            'content': self.content
        })

        if add_signature:
            obj['signature'] = self.signature
        return obj

    def verify(self, signature):
        return self.signature == signature

    @property
    def hash(self):
        hash = sha256(self.serialize()).digest()
        return b64encode(hash).decode('ascii') + '.sha256'

    @property
    def key(self):
        return '%' + self.hash


class LocalMessage(Message):
    def __init__(self, feed, content, signature=None, sequence=1, timestamp=None, previous=None):
        self.feed = feed
        self.content = content

        self.previous = previous
        if self.previous:
            self.sequence = self.previous.sequence + 1
        else:
            self.sequence = sequence

        self.timestamp = get_millis_1970() if timestamp is None else timestamp

        if signature is None:
            self.signature = self._sign()
        else:
            self.signature = signature

    def _sign(self):
        # ensure ordering of keys and indentation of 2 characters, like ssb-keys
        data = self.serialize(add_signature=False)
        return (b64encode(bytes(self.feed.sign(data))) + b'.sig.ed25519').decode('ascii')
