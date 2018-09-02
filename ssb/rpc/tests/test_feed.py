from base64 import b64decode
from collections import OrderedDict

import pytest
from nacl.signing import SigningKey, VerifyKey

from ssb.feed import LocalMessage, LocalFeed, Feed, Message, NoPrivateKeyException


SERIALIZED_M1 = b"""{
  "previous": null,
  "author": "@I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=.ed25519",
  "sequence": 1,
  "timestamp": 1495706260190,
  "hash": "sha256",
  "content": {
    "type": "about",
    "about": "@I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=.ed25519",
    "name": "neo",
    "description": "The Chosen One"
  },
  "signature": "lPsQ9P10OgeyH6u0unFgiI2wV/RQ7Q2x2ebxnXYCzsJ055TBMXphRADTKhOMS2EkUxXQ9k3amj5fnWPudGxwBQ==.sig.ed25519"
}"""


@pytest.fixture()
def local_feed():
    secret = b64decode('Mz2qkNOP2K6upnqibWrR+z8pVUI1ReA1MLc7QMtF2qQ=')
    return LocalFeed(SigningKey(secret))


@pytest.fixture()
def remote_feed():
    public = b64decode('I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=')
    return Feed(VerifyKey(public))


def test_local_feed():
    secret = b64decode('Mz2qkNOP2K6upnqibWrR+z8pVUI1ReA1MLc7QMtF2qQ=')
    feed = LocalFeed(SigningKey(secret))
    assert bytes(feed.private_key) == secret
    assert bytes(feed.public_key) == b64decode('I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=')
    assert feed.id == '@I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=.ed25519'


def test_remote_feed():
    public = b64decode('I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=')
    feed = Feed(VerifyKey(public))
    assert bytes(feed.public_key) == public
    assert feed.id == '@I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=.ed25519'

    m1 = Message(feed, OrderedDict([
        ('type', 'about'),
        ('about', feed.id),
        ('name', 'neo'),
        ('description', 'The Chosen One')
    ]), 'foo', timestamp=1495706260190)

    with pytest.raises(NoPrivateKeyException):
        feed.sign(m1)


def test_local_message(local_feed):
    m1 = LocalMessage(local_feed, OrderedDict([
        ('type', 'about'),
        ('about', local_feed.id),
        ('name', 'neo'),
        ('description', 'The Chosen One')
    ]), timestamp=1495706260190)
    assert m1.timestamp == 1495706260190
    assert m1.previous is None
    assert m1.sequence == 1
    assert m1.signature == \
        'lPsQ9P10OgeyH6u0unFgiI2wV/RQ7Q2x2ebxnXYCzsJ055TBMXphRADTKhOMS2EkUxXQ9k3amj5fnWPudGxwBQ==.sig.ed25519'
    assert m1.key == '%xRDqws/TrQmOd4aEwZ32jdLhP873ZKjIgHlggPR0eoo=.sha256'

    m2 = LocalMessage(local_feed, OrderedDict([
        ('type', 'about'),
        ('about', local_feed.id),
        ('name', 'morpheus'),
        ('description', 'Dude with big jaw')
    ]), previous=m1, timestamp=1495706447426)
    assert m2.timestamp == 1495706447426
    assert m2.previous is m1
    assert m2.sequence == 2
    assert m2.signature == \
        '3SY85LX6/ppOfP4SbfwZbKfd6DccbLRiB13pwpzbSK0nU52OEJxOqcJ2Uensr6RkrWztWLIq90sNOn1zRAoOAw==.sig.ed25519'
    assert m2.key == '%nx13uks5GUwuKJC49PfYGMS/1pgGTtwwdWT7kbVaroM=.sha256'


def test_remote_message(remote_feed):
    signature = 'lPsQ9P10OgeyH6u0unFgiI2wV/RQ7Q2x2ebxnXYCzsJ055TBMXphRADTKhOMS2EkUxXQ9k3amj5fnWPudGxwBQ==.sig.ed25519'
    m1 = Message(remote_feed, OrderedDict([
        ('type', 'about'),
        ('about', remote_feed.id),
        ('name', 'neo'),
        ('description', 'The Chosen One')
    ]), signature, timestamp=1495706260190)
    assert m1.timestamp == 1495706260190
    assert m1.previous is None
    assert m1.sequence == 1
    assert m1.signature == signature
    assert m1.key == '%xRDqws/TrQmOd4aEwZ32jdLhP873ZKjIgHlggPR0eoo=.sha256'

    signature = '3SY85LX6/ppOfP4SbfwZbKfd6DccbLRiB13pwpzbSK0nU52OEJxOqcJ2Uensr6RkrWztWLIq90sNOn1zRAoOAw==.sig.ed25519'
    m2 = Message(remote_feed, OrderedDict([
        ('type', 'about'),
        ('about', remote_feed.id),
        ('name', 'morpheus'),
        ('description', 'Dude with big jaw')
    ]), signature, previous=m1, timestamp=1495706447426)
    assert m2.timestamp == 1495706447426
    assert m2.previous is m1
    assert m2.sequence == 2
    assert m2.signature == signature
    m2.verify(signature)
    assert m2.key == '%nx13uks5GUwuKJC49PfYGMS/1pgGTtwwdWT7kbVaroM=.sha256'


def test_remote_no_signature(remote_feed):
    with pytest.raises(ValueError):
        Message(remote_feed, OrderedDict([
            ('type', 'about'),
            ('about', remote_feed.id),
            ('name', 'neo'),
            ('description', 'The Chosen One')
        ]), None, timestamp=1495706260190)


def test_serialize(local_feed):
    m1 = LocalMessage(local_feed, OrderedDict([
        ('type', 'about'),
        ('about', local_feed.id),
        ('name', 'neo'),
        ('description', 'The Chosen One')
    ]), timestamp=1495706260190)

    assert m1.serialize() == SERIALIZED_M1


def test_parse(local_feed):
    m1 = LocalMessage.parse(SERIALIZED_M1, local_feed)
    assert m1.content == {
        'type': 'about',
        'about': local_feed.id,
        'name': 'neo',
        'description': 'The Chosen One'
    }
    assert m1.timestamp == 1495706260190
