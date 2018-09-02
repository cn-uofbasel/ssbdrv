#!/usr/bin/env python3

# ssb/local/util.py

import base64
import os
import psutil

def username2dir(n):
    ssb_home = os.path.expanduser('~/.ssb')
    if not n:
        return ssb_home
    return os.path.join(ssb_home, 'user.' + n)

def is_locked(username):
    logname = username2dir(username) + '/flume/log.offset'
    for p in psutil.process_iter():
        try:
            for f in p.open_files():
                if logname in str(f):
                    print(f)
                    return p
        except:
            pass
    return None

def id2bytes(id):
    return base64.b64decode(id.split('.')[0][1:])

# eof
