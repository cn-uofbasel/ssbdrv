#!/usr/bin/env python3

# ssb/local/worm.py

import base64
import copy
import json
import hashlib
import os
import sys
import time

from ssb.local.config import verify_signature, SSB_SECRET
from ssb.local.util   import username2dir, is_locked, id2bytes

# ---------------------------------------------------------------------------

def formatMsg(prev, seq, auth, ts, hash, cont, sign):
    # returns SSB-compliant JSON string, cont still is a Python val
    if type(cont) == str:
        cont = json.dumps(cont, ensure_ascii=False)
    else:
        cont = json.dumps(cont, indent=2, ensure_ascii=False)
        cont = '\n  '.join(cont.split('\n'))
        # print(cont)
    if not prev:
        jmsg = '{\n  "previous": null,'
    else:
        jmsg = '{\n  "previous": "%s",' % prev
    jmsg += """
  "author": "%s",
  "sequence": %d,
  "timestamp": %d,
  "hash": "%s",
  "content": %s""" % (auth, seq, ts, hash, cont)
    if sign:
        jmsg = jmsg + ',\n  "signature": "%s"\n}' % sign
    else:
        jmsg = jmsg + '\n}'
    return jmsg


def _UInt32BE(buf):
    return int.from_bytes(buf, byteorder='big', signed=False)

def _readUInt32BE(f):
    return _UInt32BE(f.read(4))

def _writeUInt32BE(f, val):
    return f.write(val.to_bytes(4, byteorder='big'))

def _hthash(key):
    key = key[1:7] + '=='
    return _UInt32BE(base64.b64decode(key))

def _seq2key(key, seq):
    data = hashlib.sha1( (str(seq)+key).encode('utf8') ).digest()
    return '_' + base64.b64encode(data[:8]).decode('ascii')

# ---------------------------------------------------------------------------

class SSB_WORM_INDEX:

    def __init__(self, fname, readonly=False):
        # print('worm index is', fname)
        self._fname = fname
        if not os.path.isfile(self._fname):
            if readonly:
                raise Exception("no file", fname)
            with open(self._fname, 'wb') as ndx:
                _writeUInt32BE(ndx, 2) # vers
                _writeUInt32BE(ndx, 0) # seq?
                slots = 64*1024
                _writeUInt32BE(ndx, slots)
                _writeUInt32BE(ndx, 0) # cnt
                ndx.write(bytes(4*slots))
        self._ndxTables = []
        self._ndxDirty = False
        self._count = 0

    def load_from_disk(self):
        # read index table into memory
        self._ndxTables = []
        self._count = 0
        with open(self._fname, 'rb') as ndx:
            self._ndxHdr = ndx.read(8)
            while True:
                slots = _readUInt32BE(ndx)
                if slots == 0:
                    break
                cnt = _readUInt32BE(ndx)
                # print(slots, cnt)
                tbl = ndx.read(slots * 4)
                self._ndxTables.append( (bytearray(tbl),slots,cnt) )
                self._count += cnt
        self._ndxDirty = False

    def save_to_disk(self):
        # write back changed hash table (keys.ht)
        with open(self._fname, 'wb') as ndx:
            ndx.write(self._ndxHdr)
            for (tbl, slots, cnt) in self._ndxTables:
                _writeUInt32BE(ndx, slots)
                _writeUInt32BE(ndx, cnt)
                ndx.write(tbl)
        self._ndxDirty = False

    def add(self, key, offs):
        # add 'key at offs' to the hash table (key is a string), flag as dirty
        (tbl,slots,cnt) = self._ndxTables[-1]
        # append new hashtable if current table is full
        if cnt >= 0.5*slots:
            slots *= 2
            cnt = 0
            tbl = bytearray(4*slots)
            self._ndxTables.append( (tbl, slots, cnt) )
        # find free ht entry
        pos = _hthash(key) % slots
        while True:
            pos1 = pos+1
            val = _UInt32BE(tbl[pos*4:pos1*4])
            if val == 0:
                tbl[pos*4:pos1*4] = (offs+1).to_bytes(4, byteorder='big')
                self._ndxTables[-1] = (tbl,slots,cnt+1)
                self._ndxDirty = True
                self._count += 1
                return key
            pos = pos1 % slots
        raise Exception('internal error in hash table')

    def offsets(self, key):
        return SSB_WORM_INDEX_ITER(self._ndxTables, key)

    def flush(self):
        if not self._ndxDirty:
            return
        self.save_to_disk()

class SSB_WORM_INDEX_ITER():

    def __init__(self, ndxTables, key):
        self.h = _hthash(key)
        self.tlst = copy.copy(ndxTables)
        self.tbl, self.slots,_ = self.tlst.pop()
        self.pos = self.h % self.slots

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            pos1 = self.pos + 1
            offs = _UInt32BE(self.tbl[self.pos*4:pos1*4])
            self.pos = pos1 % self.slots
            if offs != 0:
                return offs-1
            if len(self.tlst) == 0:
                break
            self.tbl, self.slots,_ = self.tlst.pop()
            self.pos = self.h % self.slots
        raise StopIteration

# ---------------------------------------------------------------------------

class SSB_WORM:

    def __init__(self, username, secret, readonly = False):
        self._secr = secret
        self.id = self._secr.id
        self._on_extend = None
        dir = username2dir(username)
        self._blobDname = os.path.join(dir, 'blobs', 'sha256')
        if not os.path.isdir(self._blobDname):
            if readonly:
                raise Exception("no blob directory")
            os.makedirs(self._blobDname)
        self._logDname = os.path.join(dir, 'flume')
        if not os.path.isdir(self._logDname):
            if readonly:
                raise Exception("no flume directory")
            os.makedirs(self._logDname)
        self._logFname = os.path.join(self._logDname, 'log.offset')
        # print('worm log file is', self._logFname)
        if not os.path.isfile(self._logFname):
            if readonly:
                raise Exception("no log.offset file")
            with open(self._logFname, "wb") as f:
                f.write(bytes(0))
        self._readonly = readonly;
        self._log = open(self._logFname, 'rb' if readonly else 'r+b')

        self._keysHT = SSB_WORM_INDEX(os.path.join(self._logDname, 'keys.ht'),
                                      readonly)
        self._keysHT.load_from_disk() # loadKeysHT()
        if self._keysHT._count == 0:
            self._reindexKeysHT()

        self._seqsHT = SSB_WORM_INDEX(os.path.join(self._logDname, 'seqs.ht'),
                                      readonly)
        self._seqsHT.load_from_disk() # loadSeqsHT()
        if self._seqsHT._count == 0:
            self._reindexSeqsHT()

        self._lastFname = os.path.join(self._logDname, 'last.json')
        if not os.path.isfile(self._lastFname):
            self._reindexLast()
            with open(self._lastFname, "w") as f:
                json.dump(self._last, f)
        else:
            with open(self._lastFname, "rb") as f:
                self._last = json.load(f)

        # read latest (msgId,seqNo) from the log
        # self._maxSeq = self._getMaxSeq(self.id)

    def _reindexKeysHT(self):
        # print("reindexing")
        self._log.seek(0, os.SEEK_END)
        offs = self._log.tell() - 4
        while offs > 3:
            self._log.seek(offs - 4, os.SEEK_SET)
            sz = _readUInt32BE(self._log)
            self._log.seek(-4 - sz, os.SEEK_CUR)
            m = self._log.read(sz)
            offs -= sz + 12
            m = json.loads(m)
            self._keysHT.add(m['key'], offs+4)

    def _reindexSeqsHT(self):
        # print("reindexing")
        self._log.seek(0, os.SEEK_END)
        offs = self._log.tell() - 4
        while offs > 3:
            self._log.seek(offs - 4, os.SEEK_SET)
            sz = _readUInt32BE(self._log)
            self._log.seek(-4 - sz, os.SEEK_CUR)
            m = self._log.read(sz)
            offs -= sz + 12
            v = json.loads(m)['value']
            self._seqsHT.add(_seq2key(v['author'], v['sequence']), offs+4)

    def _reindexLast(self):
        # print("reindexing")
        ts = 0
        self._last = {
            'version': 1,
            'value': {},
            'seq': 0
        }
        self._log.seek(0, os.SEEK_END)
        while self._log.tell() > 8:
            self._log.seek(-8, os.SEEK_CUR)
            sz = _readUInt32BE(self._log)
            self._log.seek(-4 - sz, os.SEEK_CUR)
            msg = self._log.read(sz)
            if msg is None:
                break
            msg = json.loads(msg.decode('utf8'))
            a = msg['value']['author']
            if a in self._last['value']:
                r = self._last['value'][a]
            else:
                r = { 'sequence': 0 }
                self._last['value'][a] = r
            if r['sequence'] < msg['value']['sequence']:
                r['sequence'] = msg['value']['sequence']
                r['id'] = msg['key']
                r['ts'] = ts
            self._log.seek(-4 - sz, os.SEEK_CUR)

    def __iter__(self):
        return SSB_WORM_ITER(self)

    def _getMaxSeq(self, id=None):
        if not id:
            id = self.id
        if not id in self._last['value']:
            return (None, 0)
        r = self._last['value'][id]
        return (r['id'], r['sequence'])

        # search the log backwards for this author's newest message
        # id = self._key.id
        self._log.seek(0, os.SEEK_END)
        if self._log.tell() != 0:
            self._log.seek(-4, os.SEEK_END)
            while True:
                self._log.seek(-4, os.SEEK_CUR)
                sz = _readUInt32BE(self._log)
                self._log.seek(-4 - sz, os.SEEK_CUR)
                msg = self._log.read(sz)
                if msg is None:
                    break
                msg = json.loads(msg.decode('utf8'))
                if msg['value']['author'] == id:
                    return (msg['key'], msg['value']['sequence'])
                self._log.seek(-8 - sz, os.SEEK_CUR)
        return (None, 0)

    def _updateMaxSeq(self, id, key, seq):
        ts = 0
        self._last['value'][id] = {
            'sequence': seq,
            'id':  key,
            'ts': ts
        }

    def _fetchMsgAt(self, pos): # absolute byte position into the log
        # returns the log entry as a Python dict, or None
        self._log.seek(pos, os.SEEK_SET)
        sz = _readUInt32BE(self._log)
        msg = self._log.read(sz)
        if not msg:
            return None
        return json.loads(msg)

    def notify_on_extend(self, fct):
        # call this fct if the owner of this worm's log appends a msg
        # signature: fct(msgdict)
        self._on_extend = fct
 
    # ------------------------------------------------------------

    def blobAvailable(self, key):
        key = id2bytes(key).hex()
        return os.path.isfile(os.path.join(self._blobDname, key[:2], key[2:]))
        
    def readBlob(self, key):
        key = id2bytes(key).hex()
        with open(os.path.join(self._blobDname, key[:2], key[2:]), "rb") as f:
            data = f.read()
        return data

    def writeBlob(self, data):
        h = hashlib.sha256(data).digest()
        hx = h.hex()
        os.makedirs(os.path.join(self._blobDname, hx[:2]), exist_ok=True)
        fn = os.path.join(self._blobDname, hx[:2], hx[2:])
        if not os.path.isfile(fn):
            with open(fn, "wb") as f:
                f.write(data)
        return '&' + base64.b64encode(h).decode('ascii')

    # ------------------------------------------------------------

    def readMsg(self, key): # 256bit key in SSB representation
        for offs in self._keysHT.offsets(key):
            msg = self._fetchMsgAt(offs)
            if not msg or msg['key'] == key:
                return msg
        return None

    def getMsgBySequence(self, auth, seq):
        for offs in self._seqsHT.offsets(_seq2key(auth, seq)):
            msg = self._fetchMsgAt(offs)
            if not msg:
                return msg
            val = msg['value']
            if val['author'] == auth and val['sequence'] == seq:
                return msg
        return None

    # ------------------------------------------------------------
        
    def appendToLog(self, msgStr): # signed msg as a formatted str
        # returns id

        # validate the msg before storing:
        jmsg = json.loads(msgStr)
        if not 'author' in jmsg or not 'signature' in jmsg:
            raise ValueError
        s = base64.b64decode( jmsg['signature'] )
        i = msgStr.find(',\n  "signature":')
        m = (msgStr[:i] + '\n}').encode('utf8')
        # m = (msgStr[:i] + '\n}').encode('ascii')
        if not verify_signature(jmsg['author'], m, s):
            print("  invalid signature")
            return None
        # print("it verified!")

        # compute id
        h = hashlib.sha256(msgStr.encode('utf8')).digest()
        id = '%' + base64.b64encode(h).decode('ascii') + '.sha256'

        # check that this id is not stored yet
        if self.readMsg(id) != None:
            print("msg %s (%d) already exists" % (id, jmsg['sequence']))
            return id

        # format for storing the entry in the 'log.offset' file
        logStr = '\n  '.join(msgStr.split('\n'))
        logStr = '{\n  "key": "%s",\n  "value": ' % id + logStr + \
                 ',\n  "timestamp": %d\n}' % int(time.time()*1000)
        logStr = logStr.encode('utf8')

        if self._readonly:
            return id

        # append to the log
        self._log.close()
        self._log = open(self._logFname, 'r+b')

        self._log.seek(0, os.SEEK_END)
        offs = self._log.tell()
        sz = len(logStr).to_bytes(4, byteorder='big')
        self._log.write(sz)
        self._log.write(logStr)
        self._log.write(sz)
        pos = self._log.tell() + 4
        _writeUInt32BE(self._log, pos)
        self._log.flush()

        self._keysHT.add(id, offs)
        self._seqsHT.add(_seq2key(jmsg['author'], jmsg['sequence']), offs)

        if self._on_extend and jmsg['author'] == self.id:
            self._on_extend(json.loads(logStr))

        return id

    def writeMsg(self, msg): # msg is a Python dict or string
        # returns the new msg id
        # a) format msg as a string
        # content = '\n  '.join(json.dumps(msg, indent=2).split('\n'))
        maxs = self._getMaxSeq()
        jmsg = formatMsg(maxs[0] if maxs[0] else None,
                         maxs[1]+1, self.id,
                         int(time.time()*1000), 'sha256', msg, None)
        # b) sign and add signature field
        sig = self._secr.sign(jmsg.encode('utf8'))
        sig = base64.b64encode(sig).decode('ascii') + '.sig.ed25519'
        jmsg = jmsg[:-2] + ',\n  "signature": "%s"\n}' % sig
        # c) call append() and bump maxSeq
        id = self.appendToLog(jmsg)
        self._updateMaxSeq(self.id, id, maxs[1]+1)

        return id

    def writePrivateData(self, data, rcps):  # data is a byte array
        content = worm._secr.boxPrivateData(data, rcps)
        return worm.writeMsg(base64.b64encode(content).decode('ascii'))

    def writePrivateMsg(self, msg, rcps):  # msg is (typically) a Python dict
        msg = json.dumps(msg, ensure_ascii=False)
        return self.writePrivateData(msg.encode('utf8'), rcps)

    # ------------------------------------------------------------

    def flush(self):
        if self._readonly:
            return
        self._keysHT.flush()
        self._seqsHT.flush()
        with open(self._lastFname, "w") as f:
            json.dump(self._last, f)

    def refresh(self):
        if self._keysHT._ndxDirty or self._seqsHT._ndxDirty:
            print("warning, disregarding changed ndx information")
        self._log.close()
        self._log = open(self._logFname, 'rb' if self._readonly else 'r+b')

        self._keysHT.load_from_disk()
        self._seqsHT.load_from_disk()
        with open(self._lastFname, "rb") as f:
            self._last = json.load(f)

        
class SSB_WORM_ITER():

    def __init__(self, worm):
        # return log content BACKWARDS (youngest entry first)
        self._worm = worm
        self._log = worm._log
        self._log.seek(0, os.SEEK_END)
        self._pos = self._log.tell()
        if self._pos > 0:
            self._log.seek(-4, os.SEEK_END)
            self._pos = self._log.tell() # at end of a chunk (and its size)

    def __iter__(self):
        return self

    def __next__(self):
        # print("worm iter next", self._pos)
        if self._pos < 4:
            raise StopIteration
        self._log.seek(self._pos - 4, os.SEEK_SET)
        sz = _readUInt32BE(self._log)
        self._log.seek(-4 - sz, os.SEEK_CUR)
        m = self._log.read(sz)
        self._pos -= sz + 12
        m = json.loads(m)
        return m['key']

# ----------------------------------------------------------------------

if __name__ == '__main__':

    asecr = SSB_SECRET('Alice')
    aworm = SSB_WORM('Alice', asecr)

    for i in range(100):
        m = aworm.getMsgBySequence(asecr.id, i)
        if m:
            print(i, m['key'])

    sys.exit(0)

# eof
