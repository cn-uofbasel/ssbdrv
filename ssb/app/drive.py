#!/usr/bin/env python3

# ssb/app/drive.py - front end for a logical file system over SSB
# 2018-08-31 (c) <christian.tschudin@unibas.ch>

import cmd
from   datetime import datetime
from   fnmatch import fnmatch
import json
import os
import sys
import traceback

import ssb.adt.lfs
import ssb.local.config
import ssb.local.worm

# ---------------------------------------------------------------------------

version='2018-08-27'

class SSB_DRV_REPL:

    def __init__(self, fs, stdout=None, prefetchBlob=None):
        self.fs = fs
        self.stdout = stdout if stdout else sys.stdout
        self.prefetchBlob = prefetchBlob

    def close(self):
        self.fs.close()
        self.fs._worm.flush()
        self.print("drive deleted")

    def print(self, *args):
        self.stdout.write(' '.join([str(a) for a in args]) + '\n')

    def cat(self, remote):
        remote = os.path.split(remote)[1] # FIXME: we should follow the path
        for dent in sorted(iter(self.fs.items()), key=lambda e: e['name']):
            if dent['name'] == remote and dent['type'] == 'bindF':
                if self.fs._worm.blobAvailable(dent['blobkey']):
                    data = self.fs._worm.readBlob(dent['blobkey'])
                    self.print(data.decode('utf8'))
                    return
                # self.print("** content not available (yet)")
                if self.prefetchBlob:
                   self.prefetchBlob(dent['blobkey'])
        self.print("** no such file, or content not available (yet)")

    def cd(self, path=None):
        if not path:
            path = '/'
        try:
            self.fs.cd(path)
        except ValueError:
            self.print("** no such directory")
            return
        self.print(self.fs.getcwd())

    def get(self, remote, local=None):
        if not local:
            local = os.path.split(remote)[1]
        remote = os.path.split(remote)[1] # FIXME: we should follow the path
        for dent in sorted(iter(self.fs.items()), key=lambda e: e['name']):
            if dent['name'] == remote and dent['type'] == 'bindF':
                if self.fs._worm.blobAvailable(dent['blobkey']):
                    data = self.fs._worm.readBlob(dent['blobkey'])
                    with open(local, "wb") as f:
                        f.write(data)
                        return
                # self.print("** content not available (yet)")
                if self.prefetchBlob:
                   self.prefetchBlob(dent['blobkey'])
        self.print("** no such file, or content not available (yet)")

    def ls(self, opt=None, glob=None):
        if opt is not None and opt[0] != '-':
            glob = opt
            opt = None
        opt = '-' if not opt else opt
        dol = doh = doi = do1 = False
        for c in opt[1:]:
            if c == 'l': dol = True
            if c == 'h': doh = True
            if c == 'i': doi = True
        lines = []
        for dent in sorted(iter(self.fs.items()), key=lambda e: e['name']):
            q = r = ''
            s = dent['name']
            if glob and not fnmatch(s, glob):
                continue
            if dol:
                if 'size' in dent:
                    if doh:
                        i = int(dent['size'].bit_length()/10)
                        if i == 0:
                            r = str(dent['size'])
                        else:
                            f = 1 << (10*i)
                            r = "%d%s" % ((dent['size']+f-1)/f, ' KMGTP'[i])
                    else:
                        r = str(dent['size'])
                r += ' ' + \
                     str(datetime.utcfromtimestamp(dent['timestamp']/1000))[:19]

                if dent['type'] == 'bindF':
                    # test if referenced blob is locally available
                    if self.fs._worm.blobAvailable(dent['blobkey']):
                        q = '- '
                    else:
                        q = '-?'
                elif dent['type'] == 'bindD':
                    # test if referenced dir is locally available
                    if self.fs._worm.readMsg(dent['dirref'][1]):
                        q = 'd '
                    else:
                        q = 'd?'
                else:
                    q = 'X '
                if doi:
                    q = dent['this'][1] + ' ' + q

            # trigger proactive fetch of blobs
            if self.prefetchBlob and dent['type'] == 'bindF' and \
                            not self.fs._worm.blobAvailable(dent['blobkey']):
                self.prefetchBlob(dent['blobkey'])

            lines.append((q,r,s))
        w = 0
        for l in lines:
            if len(l[1]) > w:
                w = len(l[1])
        fmt = "%s  %{0}s %s".format(w)
        for l in lines:
            self.print(fmt % l)

    def mkdir(self, path):
        try:
            self.fs.mkdir(path)
        except ValueError:
            self.print("** no such path")

    def put(self, local, remote=None):
        with open(local, 'rb') as f:
            data = f.read()
        key = self.fs._worm.writeBlob(data)
        if not remote:
            remote = os.path.split(local)[1]
        else:
            remote = os.path.split(remote)[1] # FIXME: we should follow the path
        self.fs.linkBlob(remote, len(data), key)

    def pwd(self):
        self.print(self.fs.getcwd())

    def rename(self, glob):
        self.print("rename() not implemented")

    def rm(self, glob, bindkey=None):
        cnt = 0
        for dent in sorted(iter(self.fs.items()), key=lambda e: e['name']):
            n = dent['name']
            if glob and not fnmatch(n, glob):
                continue
            if dent['type'] != 'bindF':
                continue
            if bindkey and bindkey != dent['this'][1]:
                continue
            self.fs.unlinkBlob(dent['this'][1])
            cnt += 1
        if cnt == 0:
            self.print("** no such file")

    def rmdir(self, glob, bindkey=None):
        cnt = 0
        for dent in sorted(iter(self.fs.items()), key=lambda e: e['name']):
            n = dent['name']
            if glob and not fnmatch(n, glob):
                continue
            if dent['type'] != 'bindD':
                continue
            if bindkey and bindkey != dent['this'][1]:
                continue
            try:
                self.fs.rmdir(dent['this'][1])
            except OSError as e:
                self.print("**", e)
            cnt += 1
        if cnt == 0:
            self.print("** no such directory")
    def stat(self, opt=None, glob=None):
        if opt is not None and opt[0] != '-':
            glob = opt
            opt = None
        for dent in sorted(iter(self.fs.items()), key=lambda e: e['name']):
            if glob and not fnmatch(dent['name'], glob):
                continue
            dent['creator'] = dent['this'][0]
            dent['dentkey'] = dent['this'][1]
            del dent['this']
            self.print(dent if opt and opt == '-1' \
                       else json.dumps(dent, indent=2))

    def sync(self, arg=None):
        self.print("not implemented")

    def tree(self):
        self.print('.')
        try:
            self._tree('', self.fs._cwt.getBaseRef())
        except:
            traceback.self.print_exc()

    def _tree(self, lev, dirKey):
        if len(lev) > 75: # protect against cycles in the fs
            self.print(lev + '...')
            return
        lst = sorted(self.fs.ls(dirKey), key=lambda e:e['name'])
        cnt = len(lst)
        for dent in lst:
            x = dent['name']
            if dent['type'] == 'bindD':
                x += '/'
            cnt -= 1
            if cnt > 0:
                x = '|-- ' + x
            else:
                x = "'-- " + x
            self.print(lev + x)
            if dent['type'] == 'bindD':
                if cnt > 0:
                    self._tree(lev + '|   ', dent['dirref'])
                else:
                    self._tree(lev + '    ', dent['dirref'])


# ---------------------------------------------------------------------------

class DRIVE_CMD(cmd.Cmd):

    intro = "Secure Scuttlebutt Drive client (v%s).  Type ? for help" % version
    intro += "\nrunning in unencrypted mode"
    prompt = "ssb_drv> "

    def __init__(self, fs, prefetchBlob=None, stdout=None):
        if stdout:
            super().__init__(stdout=stdout)
        else:
            super().__init__()
        self.repl = SSB_DRV_REPL(fs, stdout, prefetchBlob)
        key = self.repl.fs._root.getBaseRef()[1]
        self.intro += "\n\n" + \
                   "drv=" + ssb.adt.lfs.uuid_from_key(self.repl.fs._worm, key)
        m = self.repl.fs._worm.readMsg(key)
        t = datetime.utcfromtimestamp(m['value']['timestamp']/1000)
        self.intro += "  (created %s)" % str(t)[:19]
        self.intro += "\ncwd='%s'" % self.repl.fs.getcwd()

    def doit(self, method, arg):
        arg = arg.split()
        try:
            method(*arg)
        except TypeError:
            c = sys._getframe(1).f_code.co_name[3:]
            traceback.print_exc()
            self.stdout.write("*** argument error\n")
            self.do_help(c)
        except:
            traceback.print_exc()
        
    def do_cat(self, arg):
        'cat  remote-path      ; display content of remote file'
        self.doit(self.repl.cat, arg)

    def do_cd(self, arg):
        'cd  path              ; change current directory'
        self.doit(self.repl.cd, arg)

    def do_get(self, arg):
        'get  remote-path [local-path]'
        self.doit(self.repl.get, arg)

    def do_ls(self, arg):
        'ls  [-lhi] [glob]     ; list directory (for names matching glob)'
        self.doit(self.repl.ls, arg)

    def do_mkdir(self, arg):
        'mkdir  path           ; make directory'
        self.doit(self.repl.mkdir, arg)

    def do_put(self, arg):
        'put  local-path [remote-path]'
        self.doit(self.repl.put, arg)

    def do_pwd(self, arg):
        'pwd                   ; print working directory'
        self.doit(self.repl.pwd, arg)
    
    def do_exit(self, arg):
        'exit                  ; end program'
        return True

    def do_rm(self, arg):
        'rm  glob [key]        ; remove file(s) matching the glob pattern'
        self.doit(self.repl.rm, arg)

    def do_rmdir(self, arg):
        'rmdir  path [key]     ; remove directory' 
        self.doit(self.repl.rmdir, arg)

    def do_stat(self, arg):
        'stat  [-1] [glob]     ; display file status (for names matching glob)'
        self.doit(self.repl.stat, arg)

    def do_sync(self, arg):
        'sync                  ; download all referenced blobs'
        self.doit(self.repl.sync, arg)

    def do_tree(self, arg):
        'tree                  ; list subtree starting from current directory'
        self.doit(self.repl.tree, arg)

    # def precmd(self, line):
    #     return line

    def emptyline(self):
        pass

    def default(self, arg):
        if arg == 'EOF':
            self.stdout.write('exit\n')
            return True
        self.stdout.write("\nUnknown command '%s'\n" % arg)
        self.do_help('')

# ---------------------------------------------------------------------------

if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser(description='SSB-Drive client')
    parser.add_argument('uuid', type=str, nargs='?',
                        help="ssb-drive's uuid (default is youngest drive")
    parser.add_argument('-user', metavar='USERNAME', type=str, dest='username',
                        help='username (default is ~/.ssb user)')
    parser.add_argument('-list', action='store_true',
                        help='list all available drives')
    parser.add_argument('-new', action='store_true',
                        help='create new drive ')
    args = parser.parse_args()

    p = ssb.local.worm.is_locked(args.username)
    if p:
        raise Exception("log file is locked by process %d (%s)" % \
                        (p.pid, p.name()))

    secr = ssb.local.config.SSB_SECRET(args.username)
    wa = ssb.local.worm.SSB_WORM(args.username, secr)
    if args.uuid:
        ref = ssb.adt.lfs.get_lfs_by_uuid(wa, args.uuid)
        if not ref:
            print("** no such drive")
            sys.exit(0)
        fs = ssb.adt.lfs.SSB_LFS(wa, ref)
    else:
        if args.list:
            print("Available SSB drives:")
            for ref in ssb.adt.lfs.find_lfs_root_iter(wa):
                m = wa.readMsg(ref[1])
                t = datetime.utcfromtimestamp(m['value']['timestamp']/1000)
                u = ssb.adt.lfs.uuid_from_key(wa, ref[1])
                print("  uuid=%s  (%s)" % (u, str(t)[:19]))
            sys.exit(0)
        if args.new:
            fs = ssb.adt.lfs.SSB_LFS(wa)
            print("new drive created, uuid=" + fs.uuid())
            sys.exit(0)

        myroot = ssb.adt.lfs.find_lfs_mostRecent(wa)
        if not myroot:
            print("** no drive found, aborting")
            sys.exit(0)

        fs = ssb.adt.lfs.SSB_LFS(wa, myroot)
        wa.flush()

    d = DRIVE_CMD(fs)

    try:
        d.cmdloop()
    except KeyboardInterrupt:
        print('^C')
    wa.flush()

# eof
