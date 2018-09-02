#!/usr/bin/env python3

# ssb-drive.py

# 2018-08-31 (c) <christian.tschudin@unibas.ch>

import array
from asyncio import gather, ensure_future, Task, get_event_loop
from datetime import datetime
import sys

from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.document import Document
from prompt_toolkit.eventloop import use_asyncio_event_loop
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import VSplit, HSplit
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.widgets import Label, TextArea, HorizontalLine

import logging
logger = logging.getLogger('packet_stream')
logger.setLevel(logging.INFO)

import ssb.adt.lfs
import ssb.app.drive
import ssb.peer.session
import ssb.local.config
import ssb.local.worm

# ---------------------------------------------------------------------------
# prompt_toolkit config:

use_asyncio_event_loop()

kb = KeyBindings()

@kb.add('c-q')
def _(event):
    event.app.exit()

@kb.add('c-c')
def _(event):
    event.app.cli.text = ''

@kb.add('c-l')
def _(event):
    event.app.renderer.clear()

@kb.add('c-i')
def _(event):
    event.app.layout.focus_next()

# ---------------------------------------------------------------------------

def make_app(fs):
    global append_to_log

    class PTK_STDOUT(): # our stdout

        def __init__(self, out):
            self.out = out

        def write(self, s):
            append(s, self.out)
            return len(s)

        def flush(self):
            pass

    class PTK_LOGGER(logging.StreamHandler):

        def __init__(self, level=logging.NOTSET, out=None):
            super().__init__(level)
            self.out = out

        def handle(self, record):
            append(record.getMessage(), self.out)
        
    def get_screen_size():
        import fcntl
        import termios

        # Buffer for the C call
        buf = array.array(u'h', [0, 0, 0, 0])
        fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, buf)
        return (buf[0], buf[1])

    def my_on_resize(old_rs_handler, fs):
        fill_top(fs)
        return old_rs_handler()
    
    # ----------------------------------------------------------------------
    # prepare the layout

    rows,_ = get_screen_size()

    top = Label('', style='reverse')
    log = TextArea(height=int((rows-4)/2), scrollbar=True)
    out = TextArea(text='\n^c: clear input,  ^l: redraw,  ^q: quit\n',
                   scrollbar=True)
    msg = Label('cwd is /', style='reverse')
    cli_args = []  # for cli_accept(), filled later

    def append(s, c=out):
        if not c:
            c.text += '\n---\n'
        if c == log:
            s = s.split('\n')[0][:get_screen_size()[1]-2] + '\n'
        t = c.text + s
        c.buffer.document = Document(text=t, cursor_position=len(t)-1)

    def cli_accept(buf):
        app, cli, fs = cli_args
        append('\n---\n> ' + cli.text + '\n')
        app.cmd.onecmd(cli.text)
        msg.text = 'cwd is ' + fs.getcwd()
        cli.buffer.history.append_string(cli.text)
        cli.text = ''

    def fill_top(fs):
        s1 = ' SSB Drive' #  (v20180831)'
        s2 = '[uuid ' + fs.uuid() + '] '
        w = get_screen_size()[1]
        top.text = s1 + ' '*(w-len(s1)-len(s2)) + s2
    
    cli = TextArea(multiline=False, accept_handler=cli_accept)
    bot = VSplit([ Label('> ', dont_extend_width=True), cli ])
    top_container = HSplit([ top,
                             log, HorizontalLine(),
                             out, msg, bot ])

    app = Application(Layout(top_container), key_bindings=kb, full_screen=True)
    cli_args += [app, cli, fs] # for cli_accept()
    app.cli = cli  # for retrieving it in the keyboard handler
    app.layout.focus(cli)
    fill_top(fs)

    old_rs_resize = app._on_resize
    app._on_resize = lambda : my_on_resize(old_rs_resize, fs)
    app.stdout = PTK_STDOUT(out) # used for cmd

    logging.getLogger('packet_stream').addHandler(PTK_LOGGER(out=log))

    return app

# ---------------------------------------------------------------------------

if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser(description='SSB-Drive client')
    parser.add_argument('-del', dest='delete', action='store_true',
                        help="del drive")
    parser.add_argument('-list', action='store_true',
                        help='list all active drives')
    parser.add_argument('-new', action='store_true',
                        help='create new drive ')
    parser.add_argument('-peer', metavar='IP:PORT:ID',
                        help="remote's ip:port:id " + \
                             "(default is localhost:8008:default_id")
    parser.add_argument('-port',
                        help="local port (i.e. become a server)")
    parser.add_argument('-sync', action='store_true',
                        help="sync log and exit")
    parser.add_argument('-tty', action='store_true',
                        help='run in line mode (instead of fullscreen terminal)')
    parser.add_argument('-user', type=str, metavar='USERNAME', dest='username',
                        help='username (default is ~/.ssb user)')
    parser.add_argument('-udel', action='store_true',
                        help="undelete drive")
    parser.add_argument('uuid', type=str, metavar='UUID', nargs='?',
                        help="ssb-drive's uuid (default is youngest drive)")

    args = parser.parse_args()
    sess = ssb.peer.session.SSB_SESSION(args.username)

    if args.sync:
        if args.port:
            print("** cannot be server for syncing, aborting")
        else:
            logger.addHandler(logging.StreamHandler())
            theLoop = get_event_loop()
            try:
                theLoop.run_until_complete(ssb.peer.session.main(args, sess))
            finally:
                sess.worm.flush()
                for t in Task.all_tasks():
                    t.cancel()
                theLoop.close()
        sys.exit(0)

    if args.uuid:
        ref = ssb.adt.lfs.get_lfs_by_uuid(sess.worm, args.uuid)
        if not ref:
            print("** no such drive")
            sys.exit(0)
        fs = ssb.adt.lfs.SSB_LFS(sess.worm, ref)
        if args.udel:
            print("** not implemented")
            sys.exit(0)
        if args.delete:
            fs.close()
            sess.worm.flush()
            print("**", args.uuid, "was deleted")
            sys.exit(0)
    else:
        if args.delete or args.udel:
            print("** must specify a drive")
            sys.exit(0)
        if args.list:
            print("Available SSB drives:")
            for ref in ssb.adt.lfs.find_lfs_root_iter(sess.worm):
                m = sess.worm.readMsg(ref[1])
                t = datetime.utcfromtimestamp(m['value']['timestamp']/1000)
                u = ssb.adt.lfs.uuid_from_key(sess.worm, ref[1])
                print("  uuid=%s  (%s)" % (u, str(t)[:19]))
            sys.exit(0)
        if args.new:
            fs = ssb.adt.lfs.SSB_LFS(sess.worm)
            sess.worm.flush()
            print("** new drive created, uuid=" + fs.uuid())
            sys.exit(0)

        myroot = ssb.adt.lfs.find_lfs_mostRecent(sess.worm)
        if not myroot:
            print("** no drive found, aborting")
            sys.exit(0)

        fs = ssb.adt.lfs.SSB_LFS(sess.worm, myroot)
        sess.worm.flush()

    if args.tty:
        d = ssb.app.drive.DRIVE_CMD(fs)
        try:
            d.cmdloop()
        except KeyboardInterrupt:
            print('^C')
        sess.worm.flush()
    else:
        app = make_app(fs)
        app.cmd = ssb.app.drive.DRIVE_CMD(fs, stdout=app.stdout,
                                          prefetchBlob= lambda k: \
                           ensure_future(ssb.peer.session.fetch_blob(sess, k)))

        theLoop = get_event_loop()
        ensure_future(ssb.peer.session.main(args, sess))
        try:
            theLoop.run_until_complete(app.run_async().to_asyncio_future())
        finally:
            sess.worm.flush()
            for t in Task.all_tasks():
                t.cancel()
            theLoop.close()

# eof
