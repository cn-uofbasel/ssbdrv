#!/usr/bin/env python3

# ssb_local/config.py

import base64
import json
import nacl.signing
import os
import sys

def username2dir(n):
    ssb_home = os.path.expanduser('~/.ssb')
    if not n:
        return ssb_home
    return os.path.join(ssb_home, 'user.' + n)

def id2bytes(id):
    return base64.b64decode(id.split('.')[0][1:])

def verify_signature(id, data, sig):
    if type(data) == str:
        data = data.encode('utf8')
    vk = nacl.signing.VerifyKey(base64.b64decode(id[1:-8]))
    try:
        vk.verify(data, sig)
        return True
    except:
        return False

def load_ssb_secret(fname=None):
    if not fname:
        fname = os.path.expanduser('~/.ssb/secret')
    with open(fname, 'r') as f:
        s = json.loads('\n'.join([l for l in f.read().split('\n') \
                                  if len(l) > 0 and l[0] != '#']))
    return s
    
# ----------------------------------------------------------------------

secret_prologue = """# this is your SECRET name.
# this name gives you magical powers.
# with it you can mark your messages so that your friends can verify
# that they really did come from you.
#
# if any one learns this name, they can use it to destroy your identity
# NEVER show this to anyone!!!

"""

secret_epilogue = """

# WARNING! It's vital that you DO NOT edit OR share your secret name
# instead, share your public name
# your public name: """

# ----------------------------------------------------------------------

def create_new_user_secret(path):
    sik = nacl.signing.SigningKey.generate()
    s = {
        'curve' : 'ed25519',
        'private' : base64.b64encode(sik._signing_key).decode('ascii') \
                            + '.ed25519',
        'public' :  base64.b64encode(sik.verify_key._key).decode('ascii') \
                            + '.ed25519'
    }
    s['id'] = '@' + s['public']
    with open(path, "w") as f:
        f.write(secret_prologue)
        f.write(json.dumps(s, indent=2))
        f.write(secret_epilogue + (s['id'] + '\n'))
    
class SSB_SECRET:

    def __init__(self, username=None, create=False):
        dirname = username2dir(username)
        fname = os.path.join(dirname, 'secret')
        if not os.path.isfile(fname):
            if not create:
                raise Exception("no file with secret")
            create_new_user_secret(fname)
        s = load_ssb_secret(fname)
        if s['curve'] != 'ed25519':
            raise Exception("unknown curve %s in %s" % \
                            (s['curve'], fname))
        self._secr = s
        self.id = self._secr['id']
        self.pk = base64.b64decode(self._secr['public'][:-8])
        self.pkc = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(self.pk)
        self.sk = base64.b64decode(self._secr['private'][:-8])
        self.skc = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(self.sk)
        self.keypair = nacl.signing.SigningKey(base64.b64decode(self._secr['private'][:-8])[:32])

    def sign(self, data):
        return nacl.bindings.crypto_sign(data, self.sk)[:64]

    def _sbox_open(self, data, nonce, key):
        return nacl.bindings.crypto_secretbox_open(data, nonce, key)

    def boxPrivateData(self, data, rcpts):
        # returns the ciphertext (bytes)
        if len(rcpts) > 8:
            return None
        kp = nacl.bindings.crypto_box_keypair()
        keks = []  # key encryption keys
        for r in rcpts:
            r = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(id2bytes(r))
            keks.append(nacl.bindings.crypto_scalarmult(kp[1], r))
        nonce = nacl.bindings.randombytes(24)
        dek = nacl.bindings.randombytes(32)
        ndek = bytes([len(rcpts)]) + dek
        c = nonce + kp[0] # nonce followed by public key
        for k in keks:    # append wrapped deks for all recpts
            c += nacl.bindings.crypto_secretbox(ndek, nonce, k)
        return c + nacl.bindings.crypto_secretbox(data, nonce, dek)

    def unboxPrivateData(self, data): # ciphertext
        # returns decoded data (bytes)
        nonce = data[:24]
        mykek = nacl.bindings.crypto_scalarmult(self.skc, data[24:56])
        rcpts = data[56:]
        for i in range(8):
            if len(rcpts) < 49:
                return None
            try:
                dek = self._sbox_open(rcpts[:49], nonce, mykek)
                return self._sbox_open(data[56+dek[0]*49:], nonce, dek[1:])
            except:
                pass
            rcpts = rcpts[49:]
        return None

# ---------------------------------------------------------------------------

if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser(description='SSB-Drive configurator')
    parser.add_argument('-new', type=str, metavar='USERNAME',
                        help="create new user")
    parser.add_argument('-friends', nargs=2, metavar='NAME',
                        help="make two users follow each other")
    parser.add_argument('-list', action='store_true',
                        help='list all users')
    args = parser.parse_args()
    ssb_home = os.path.expanduser('~/.ssb')
        
    if args.list:
        fname = os.path.join(ssb_home, 'secret')
        s = load_ssb_secret(fname)
        print("default user:\n  %s" % s['id'])
        print("local users:")
        for e in os.listdir(ssb_home):
            fname = os.path.join(ssb_home, e, 'secret')
            e = e.split('.')
            if e[0] == 'user':
                s = load_ssb_secret(fname)
                print("  %s  %s" % (s['id'], e[1]))
    elif args.friends:
        fn = ['', '']
        s = [None, None]
        fr = [None, None]
        for i in range(2):
            fn[i] = username2dir(args.friends[i])
            s[i] = load_ssb_secret(os.path.join(fn[i], 'secret'))
            fn[i] = os.path.join(fn[i], 'flume')
            if not os.path.isdir(fn[i]):
                os.mkdir(fn[i])
            fn[i] = os.path.join(fn[i], 'friends.json')
            if not os.path.isfile(fn[i]):
                with open(fn[i], 'w') as f:
                    f.write(json.dumps({
                        'seq': 0,
                        'version': 2,
                        'value': {
                            s[i]['id'] : {}
                        }
                    }))
            with open(fn[i], 'r') as f:
                fr[i] = json.load(f)
        if not s[0]['id'] in fr[1]['value'][s[1]['id']]:
            fr[1]['value'][s[1]['id']][s[0]['id']] = True
        if not s[1]['id'] in fr[0]['value'][s[0]['id']]:
            fr[0]['value'][s[0]['id']][s[1]['id']] = True
        for i in range(2):
            with open(fn[i], 'w') as f:
                f.write(json.dumps(fr[i]))
        print("** friend records updated")
    elif args.new:
        dname = username2dir(args.new)
        if os.path.isdir(dname) or os.path.isfile(dname):
            print("** user already exists, aborting")
            sys.exit(0)
        os.mkdir(dname)
        sname = os.path.join(dname, 'secret')
        create_new_user_secret(sname)
        os.mkdir(os.path.join(dname, 'flume'))
        s = load_ssb_secret(sname)
        print('** new user %s (%s)' % (args.new, s['id']))
    else:
        print("** ?")

# eof
