#!/usr/bin/env python3

# ssb/adt/lfs.ps
# logical file system for SSB

import copy
from datetime import datetime
import os
import sys
import uuid

import ssb.adt.tangle

# ---------------------------------------------------------------------------

# this is the UUID for the SSB filesystem namespace
# (we picked a random UUID and let it start with 'SSB', hex-alike)
NS_UUID = '55bf2f4d-9915-4d86-a76f-7b7d6888c107'

def uuid_from_key(worm, key):
    # key is a string
    try:
        m = worm.readMsg(key)
        salt = '' # backwards compatibility with initial version
        if 'salt' in m['value']['content']:
            salt = m['value']['content']['salt']
    except:
        return None
    ns = uuid.UUID(NS_UUID)
    return str(uuid.uuid5(ns, salt+key))

tag_lfs_root = 'ssb_lfs:v1:root' # drive node
tag_lfs_dir  = 'ssb_lfs:v1:dir'  # directory node
# tag_lfs_cmd  = 'ssb_lfs:v1:cmd'  # command

# ----------------------------------------------------------------------

"""

root tangle record for a drive:

  'type': 'tangle'
  'use': 'ssb_lfs:v1:root',
  'salt': NNN

directory tangle record for a drive:

  'type': 'tangle'
  'use': 'ssb_lfs:v1:dir',
  'drvref: [ '@..', '%..' ]

content INSIDE a tangle record for directory entries (dent):

* bind name to file:
     { 'type': 'bindF', 'name': '..', 'size': xx, 'blobkey': '%..' }

* bind name to subdirectory:
     { 'type': 'bindD', 'name': '..', 'dirref': [ '@..', '%..' ] }

* unbind:
     { 'unbind': 'unbind', 'key': '%..' }
     'key' points to one of the above definition records

* close (block) a drive:
     { 'type': 'blocked' }


not implemented yet:

* record for symlink (bindL / 'name' / path)
* record for mount, umount
* directory snapshots

"""

class SSB_LFS:

    def __init__(self, worm, rootRef=None, owners=None):
        self._worm = worm
        self._root = ssb.adt.tangle.SSB_TANGLE(worm, rootRef,
                                               # in case a new root is created:
                                               use=tag_lfs_root,
                                               salt=os.urandom(8).hex())
        self._cwt  = self._root  # current working tangle
        self._pars = [self._cwt] # list of parent tangles
        self._path = ['']        # list of strings

    def uuid(self):
        return uuid_from_key(self._worm, self._root.base[1])

    def items(self): # iterate through cwd
        self._cwt.refresh()
        return LFS_ITER(self._worm, self._cwt, None)

    def ls(self, dirref): # iterate through this dir tagle
        dir = ssb.adt.tangle.SSB_TANGLE(self._worm, dirref)
        return LFS_ITER(self._worm, dir, None)

    def getcwd(self): # get current working directory
        return '/' + '/'.join(self._path[1:])

    def close(self):
        self._root.append({ 'type': 'blocked' })

    def cd(self, path): # change directory
        new_pars = copy.copy(self._pars)
        new_path = copy.copy(self._path)
        path = os.path.normpath(path)
        if path[0] == '/':
            path = path[1:]
            new_pars = new_pars[:1]
            new_path = new_path[:1]
        new_cwt = new_pars[-1]
        if len(path) > 0:
            for p in path.split('/'):
                if p == '.':
                    continue
                if p == '..':
                    if len(new_path) > 1:
                        new_pars.pop()
                        new_path.pop()
                    new_cwt = new_pars[-1]
                else:
                    for dent in LFS_ITER(self._worm, new_cwt, None):
                        if dent['name'] == p and dent['type'] == 'bindD':
                            break
                    else:
                        raise ValueError
                    new_cwt = ssb.adt.tangle.SSB_TANGLE(self._worm, dent['dirref'])
                    new_pars.append(new_cwt)
                    new_path.append(p)
        self._cwt = new_cwt
        self._pars = new_pars
        self._path = new_path

    def mkdir(self, n):
        # FIXME: refuse if target name exists
        dirtan = ssb.adt.tangle.SSB_TANGLE(self._worm,
                                           use=tag_lfs_dir,
                                           drv=self._root.getBaseRef())
        self._cwt.append({
            'type': 'bindD',
            'name': n,
            'dirref' : dirtan.getBaseRef(),
        })

    def rmdir(self, bindkey):
        # FIXME: make sure that the entry is part of this file system
        for dent in iter(self.items()):
            if dent['this'][1] == bindkey:
                if dent['type'] != 'bindD':
                    raise OSError
                dir = ssb.adt.tangle.SSB_TANGLE(self._worm, dent['dirref'])
                for e in LFS_ITER(self._worm, dir, None): # must be empty
                    raise OSError("directory not empty")
                self._cwt.append({
                    'type': 'unbind',
                    'key': bindkey
                })
                return
        raise ValueError("no such directory entry")

    def linkBlob(self, n, size, key, overwrite=False):
        # FIXME: refuse if target name exists and is a dir
        self._cwt.append({
            'type': 'bindF',
            'name': n,
            'size': size,
            'blobkey' : key,
        })
        # FIXME: if overwrite: remove all files with the given name

    def unlinkBlob(self, bindkey):
        # FIXME: make sure that the entry is part of this file system
        for dent in iter(self.items()):
            if dent['this'][1] == bindkey:
                if dent['type'] != 'bindF':
                    raise OSError
                self._cwt.append({
                    'type': 'unbind',
                    'key': bindkey
                })
                return
        raise ValueError

    """
    def rename(self, new, old, key=None):
        # FIXME: make sure that the orig entry is part of this file system
        # FIXME: refuse if target name exists and is a dir
        # FIXME: refuse if it's a dir and target would create a cycle
        # FIXME: create target
        # FIXME: if file and overwrite: remove all files with the given name
        # FIXME: unlink/rm original entry
        pass
    """


class LFS_ITER:

    def __init__(self, worm, tang, cwdRef):
        # print("fs_iter")
        self._worm = worm
        self._tang = tang
        # self._cwd = cwdRef
        self._tomb = []
        for k in tang:
            dent = self._worm.readMsg(k)
            if dent['value']['content']['content']['type'] == 'unbind':
                # print('tombstone', k, dent['key'])
                self._tomb.append(dent['value']['content']['content']['key'])
        # print('tomb', [t[:10] for t in self._tomb])
        self._iter = iter(tang)

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            k = self._iter.__next__()
            # print(".. ", k)
            if k in self._tomb:
                continue
            bind = self._worm.readMsg(k)
            if bind['value']['content']['content']['type'] == 'unbind':
                continue;
            # print('ok to go:', k)
            r = copy.copy(bind['value']['content']['content'])
            r['this'] = [bind['value']['author'], bind['key']]
            r['timestamp'] = bind['value']['timestamp']
            return r

# ---------------------------------------------------------------------------

class LFS_ROOT_ITER:
    
    def __init__(self, worm):
        # print("lfs_root_iter for", worm._logFname)
        self._worm = worm
        self._i = iter(worm)
        self._closed = []
        self._found = []

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            k = self._i.__next__()
            if k in self._closed:
                continue
            m = self._worm.readMsg(k)
            if not m:
                continue
            c = m['value']['content']
            if type(c) == dict and c['type'] == 'tangle':
                try:
                    if c['content']['type'] == 'blocked' and \
                                       m['value']['author'] == self._worm.id:
                        k = c['base'][1]
                        # print(k)
                        if not k in self._closed:
                            self._closed.append(k)
                        continue
                except:
                    pass
                # fetch root node by folllowing the base ref
                if 'base' in c:
                    k = c['base'][1]
                    m = self._worm.readMsg(k)
                    if not m:
                        continue
                    c = m['value']['content']
                    if type(c) != dict or c['type'] != 'tangle':
                        continue
                if not 'use' in c or c['use'] != tag_lfs_root or \
                                                      m['key'] in self._found:
                    continue
                self._found.append(m['key'])
                return [m['value']['author'], m['key']]
        raise StopIteration

def find_lfs_root_iter(worm):
    return LFS_ROOT_ITER(worm)

def find_lfs_mostRecent(worm):
    # find our most recently defined FS in the log
    for ref in find_lfs_root_iter(worm):
        # if ref[0] == worm.id: # return with first match
        return ref
    return None

def get_lfs_by_uuid(worm, uuid):
    for ref in find_lfs_root_iter(worm):
        if uuid == uuid_from_key(worm, ref[1]):
            return ref
    return None

# ---------------------------------------------------------------------------
if __name__ == '__main__' :

    import ssb.local.config
    import ssb.local.worm

    asecr = ssb.local.config.SSB_SECRET('Alice')
    aworm = ssb.local.worm.SSB_WORM('Alice', asecr)

    for dent in find_lfs_root_iter(aworm):
        print(dent)

# eof

