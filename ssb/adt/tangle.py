#!/usr/bin/env python3

# ssb/adt/tangle.py

import copy

import ssb.local.worm

class SSB_TANGLE:

    def __init__(self, worm, baseName=None, use=None, salt=None, drv=None):
        self.worm = worm
        if not baseName: # create a new tangle
            m = {'type': 'tangle', 'height': 0}
            if use:
                m['use'] = use
            # FIXME: should these entries be in the tangle record *content*?
            if salt:
                m['salt'] = salt
            if drv:
                m['drvref'] = drv
            key = worm.writeMsg(m)
            worm.flush()
            self.base = [worm.id, key]
        else:
            self.base = baseName
        self.tips, self.height = self._getTips()

    def _getTips(self, stop=None):
        # print("searching", self.base[1])
        # search the log backwards for any tangle msg for 'base'
        allx = []
        for k in self.worm:
            if k == self.base[1]:
                allx.append(k)
                continue
            msg = self.worm.readMsg(k)
            if msg == None:
                # print("no msg for", key)
                continue
            tan = msg['value']['content']
            if not isinstance(tan,dict) or tan['type'] != 'tangle':
                continue
            if 'base' in tan:
                # print(k, tan['base'])
                if tan['base'][1] == self.base[1]:
                    allx.append(k)
        tips = copy.copy(allx)
        for k in allx:
            msg = self.worm.readMsg(k)
            if msg == None:
                # print("no msg for", key)
                continue
            tan = msg['value']['content']
            if 'base' in tan and tan['base'][1] in tips:
                tips.remove(tan['base'][1])
            if 'previous' in tan:
                for p in tan['previous']:
                    if p[1] in tips:
                        tips.remove(p[1])
        maxH = 0
        for k in tips:
            msg = self.worm.readMsg(k)
            h = msg['value']['content']['height']
            if  h > maxH:
                maxH = h
        allx = tips
        tips = []
        for k in allx:
            msg = self.worm.readMsg(k)
            tan = msg['value']['content']
            tips.append( (msg['value']['author'], k, tan['height']) )
        # print(tips, maxH)
        return (tips, maxH)

    def getBaseRef(self):
        return self.base

    def append(self, content, previous=None):
        if self.tips is None:
            raise Exception("can't find tangle")
        # print("append, #tips is", len(self.tips), "/ height", type(self.height))
        msg = {
            'type'     : 'tangle',
            'base'     : self.base,
            # 'height'   : self.height + 1,
            'content'  : content
        }
        if previous is None:
            previous = self.tips[:3]
            msg['previous'] = previous   # merge up to three branches
            msg['height'  ] = self.height + 1
        else:
            msg['previous'] = [previous] # only point to one branch
            msg['height'  ] = self.worm.readMsg(previous[1])['value']['content']['height'] + 1
            previous = []
        ref = [self.worm.id, self.worm.writeMsg(msg)]
        self.tips = self.tips[len(previous):]
        self.tips.append(ref)
        self.height += 1
        # print("  #tips now is", len(self.tips), "/ height", self.height)
        # for t in self.tips:
        #     print("    ", t[1])
        return ref

    def __iter__(self):
        return SSB_TANGLE_ITER(self.worm, self.tips)

    def refresh(self):
        self.worm.flush()
        self.worm.refresh()
        self.tips, self.height = self._getTips(self.tips)


class SSB_TANGLE_ITER:

    def __init__(self, worm, tips):
        self.worm = worm
        self.front = [ (k[1], self.worm.readMsg(k[1])['value']['content'])
                                      for k in tips ]
        self.expanded = []

    def __iter__(self):
        return self

    def __next__(self):
        while len(self.front) > 0:
            # find highest element
            self.front = sorted(self.front,
                                key=lambda e: float("%d.%d" % \
                                     (e[1]['height'],
                                      ssb.local.worm._hthash(e[0]))))
            k, m = self.front.pop()
            self.expanded.append(k)
            if 'previous' in m: # don't return the genesis node
                for p in m['previous']:
                    if p[1] in self.expanded:
                        continue
                    m2 = self.worm.readMsg(p[1])
                    if not m2:
                        continue
                    e = (p[1], m2['value']['content'])
                    if not e in self.front:
                        self.front.append(e)
                return k
        raise(StopIteration)

    
# ---------------------------------------------------------------------------
if __name__ == '__main__' :

    pass

# eof

