# ssb/shs/crypto.py

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
import hmac
from base64 import b64decode

from nacl.bindings import (crypto_box_afternm, crypto_box_open_afternm,
                           crypto_scalarmult)
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from nacl.signing import VerifyKey

APPLICATION_KEY = b64decode('1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=')


class SHSError(Exception):
    """A SHS exception."""
    pass


class SHSCryptoBase(object):
    def __init__(self, local_key, ephemeral_key=None, application_key=None):
        self.local_key = local_key
        self.application_key = application_key or APPLICATION_KEY
        self._reset_keys(ephemeral_key or PrivateKey.generate())

    def _reset_keys(self, ephemeral_key):
        self.local_ephemeral_key = ephemeral_key
        self.local_app_hmac = (hmac.new(self.application_key, bytes(ephemeral_key.public_key), digestmod='sha512')
                               .digest()[:32])

    def generate_challenge(self):
        """Generate and return a challenge to be sent to the server."""
        return self.local_app_hmac + bytes(self.local_ephemeral_key.public_key)

    def verify_challenge(self, data):
        """Verify the correctness of challenge sent from the client."""
        assert len(data) == 64
        sent_hmac, remote_ephemeral_key = data[:32], data[32:]

        h = hmac.new(self.application_key, remote_ephemeral_key, digestmod='sha512')
        self.remote_app_hmac = h.digest()[:32]
        ok = self.remote_app_hmac == sent_hmac

        if ok:
            # this is (a * b)
            self.shared_secret = crypto_scalarmult(bytes(self.local_ephemeral_key), remote_ephemeral_key)
            self.remote_ephemeral_key = remote_ephemeral_key
            # this is hash(a * b)
            self.shared_hash = hashlib.sha256(self.shared_secret).digest()
        return ok

    def clean(self, new_ephemeral_key=None):
        self._reset_keys(new_ephemeral_key or PrivateKey.generate())
        self.shared_secret = None
        self.shared_hash = None
        self.remote_ephemeral_key = None

    def get_box_keys(self):
        shared_secret = hashlib.sha256(self.box_secret).digest()
        return {
            'shared_secret': shared_secret,
            'encrypt_key': hashlib.sha256(shared_secret + bytes(self.remote_pub_key)).digest(),
            'decrypt_key': hashlib.sha256(shared_secret + bytes(self.local_key.verify_key)).digest(),
            'encrypt_nonce': self.remote_app_hmac[:24],
            'decrypt_nonce': self.local_app_hmac[:24]
        }


class SHSServerCrypto(SHSCryptoBase):
    def verify_client_auth(self, data):
        assert len(data) == 112
        a_bob = crypto_scalarmult(bytes(self.local_key.to_curve25519_private_key()), self.remote_ephemeral_key)
        box_secret = hashlib.sha256(self.application_key + self.shared_secret + a_bob).digest()
        self.hello = crypto_box_open_afternm(data, b'\x00' * 24, box_secret)
        signature, public_key = self.hello[:64], self.hello[64:]
        signed = self.application_key + bytes(self.local_key.verify_key) + self.shared_hash
        pkey = VerifyKey(public_key)

        # will raise an exception if verification fails
        pkey.verify(signed, signature)
        self.remote_pub_key = pkey
        b_alice = crypto_scalarmult(bytes(self.local_ephemeral_key),
                                    bytes(self.remote_pub_key.to_curve25519_public_key()))
        self.box_secret = hashlib.sha256(self.application_key + self.shared_secret + a_bob + b_alice).digest()[:32]
        return True

    def generate_accept(self):
        okay = self.local_key.sign(self.application_key + self.hello + self.shared_hash).signature
        d = crypto_box_afternm(okay, b'\x00' * 24, self.box_secret)
        return d

    def clean(self, new_ephemeral_key=None):
        super(SHSServerCrypto, self).clean(new_ephemeral_key=new_ephemeral_key)
        self.hello = None
        self.b_alice = None


class SHSClientCrypto(SHSCryptoBase):
    """An object that encapsulates all the SHS client-side crypto.

    :param local_key: the keypair used by the client (:class:`nacl.public.PrivateKey` object)
    :param server_pub_key: the server's public key (``byte`` string)
    :param ephemeral_key: a fresh local :class:`nacl.public.PrivateKey`
    :param application_key: the unique application key (``byte`` string), defaults to SSB's
    """

    def __init__(self, local_key, server_pub_key, ephemeral_key, application_key=None):
        super(SHSClientCrypto, self).__init__(local_key, ephemeral_key, application_key)
        self.remote_pub_key = VerifyKey(server_pub_key)

    def verify_server_challenge(self, data):
        """Verify the correctness of challenge sent from the server."""
        assert super(SHSClientCrypto, self).verify_challenge(data)
        curve_pkey = self.remote_pub_key.to_curve25519_public_key()

        # a_bob is (a * B)
        a_bob = crypto_scalarmult(bytes(self.local_ephemeral_key), bytes(curve_pkey))
        self.a_bob = a_bob
        # this shall be hash(K | a * b | a * B)
        self.box_secret = hashlib.sha256(self.application_key + self.shared_secret + a_bob).digest()

        # and message_to_box will correspond to H = sign(A)[K | Bp | hash(a * b)] | Ap
        signed_message = self.local_key.sign(self.application_key + bytes(self.remote_pub_key) + self.shared_hash)
        message_to_box = signed_message.signature + bytes(self.local_key.verify_key)
        self.hello = message_to_box
        return True

    def generate_client_auth(self):
        """Generate box[K|a*b|a*B](H)"""

        nonce = b"\x00" * 24
        # return box(K | a * b | a * B)[H]
        return crypto_box_afternm(self.hello, nonce, self.box_secret)

    def verify_server_accept(self, data):
        """Verify that the server's accept message is sane"""
        curve_lkey = self.local_key.to_curve25519_private_key()
        # b_alice is (A * b)
        b_alice = crypto_scalarmult(bytes(curve_lkey), self.remote_ephemeral_key)
        self.b_alice = b_alice
        # this is hash(K | a * b | a * B | A * b)
        self.box_secret = hashlib.sha256(self.application_key + self.shared_secret + self.a_bob +
                                         b_alice).digest()

        nonce = b"\x00" * 24

        try:
            # let's use the box secret to unbox our encrypted message
            signature = crypto_box_open_afternm(data, nonce, self.box_secret)
        except CryptoError:
            raise SHSError('Error decrypting server acceptance message')

        # we should have received sign(B)[K | H | hash(a * b)]
        # let's see if that signature can verify the reconstructed data on our side
        self.remote_pub_key.verify(self.application_key + self.hello + self.shared_hash, signature)
        return True

    def clean(self, new_ephemeral_key=None):
        super(SHSClientCrypto, self).clean(new_ephemeral_key=new_ephemeral_key)
        self.a_bob = None
        self.b_alice = None
