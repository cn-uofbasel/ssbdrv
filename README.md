# SSB Drive

This is a proof of concept for a **decentralized file system for Secure
Scuttlebutt** (see [SSB](https://www.scuttlebutt.nz/)). It includes a
partial but interoperable implementation of the SSB peer protocol written
in Python.

With _SBB Drive_ you can create as many file systems ("drives") as you
like, share and organize files with your friends without requiring a
central repository or server. When you work on your files while
offline, the _SSB Drive_ file system will merge automatically with the
rest of the world once you rejoin the grid. Name conflicts are handled
with "Observed Removed Sets" (OR-Sets) from CRDT.

Main usage:

```txt
$ ./ssb-drive.py [-u USERNAME] [-l] [-peer ip:port:id] [UUID]
```

where UUID identifies the drive to work on. Use `-l` to list all
available drives. The `-peer` option selects a specific SSB pub (peer
node); the default behavior is to connect to the locally running SSB
program at port 8008 (e.g. patchwork or sbot).

__Code status:__ This is a proof-of-concept and is not a well-curated
Python package, it also lacks testing routines. __DON'T RUN THIS CODE
ON YOUR LOG__: It's very hard --and often impossible-- to correct a
corrupted hash chain especially if it has leaked into the global SSB
system. Please read the section "Experimenting with SSB Drive" for
safe ways to work locally - you have been warned.

Best is to unpack this Git repo and just run from the `ssbdrv`
directory after installing the dependencies (see
`requirements.txt`). In the future, when the internal interfaces of
`ssbdrv` have stabilized, a full Python package will be provided,
probably also factoring out the SSB peer-to-peer component as an
independent package. We acknowledge the import of pferreir's
[`pyssb`](https://github.com/pferreir/pyssb) package which had to be
made more complete: The modified `pyssb` code is included for
convenience, making this `ssbdrv` repo self-contained.

__Doc status__: Read the source, Luke. Moreover, there is a draft document
on tangles for SSB in this Git repo, see
['The Tangle data structure and its use in SSB Drive'](doc/tangle.md)

## Demo

_SSB Drive_ behaves like a classic FTP client except that you don't have
to connect to a server. The following demo shows the terminal-based user
interface of this PoC.

![demo-20180831.gif](doc/demo-20180831.gif)

What can be seen in the 30 second animated GIF:

```txt
Alice:  help                  // list available commands
Alice:  ls -l                 // show dir content
Bob:    ls -l                 // Bob sees same content
Bob:    put b.txt             // Bob uploads a file
Alice:  ls -l                 // Alice finds it in her directory
Alice:  cat b.txt             //  and views it
Alice:  put x.txt first.txt   // Alice races to upload first
Bob:    put y.txt first.txt   // Bob races to upload first
Bob:    ls -l                 // surprise: no race condition, but two files
Bob:    tree                  // just another view
Bob:    ls -li                // UNIX -i option: show inode (cypherlink in our case)
                              // i.e., the two files differ, can be removed individually
```

## Pragmatics

Without UUID argument, the app first scans your SSB log and uses the
most recent "root entry" it can find as the work drive -- beware that
this drive could have been created by a friend.  If you know the drive
that you want to use (e.g. if you created several drives and/or want
to be sure to work on a specific one), you should pass that drive's
UUID as an argument.

You can request the creation of a new drive with the `-n` option and list
all available drives with `-l`.

Because SSB is based on append-only logs, all changes ever made to a
drive are preserved for as long as the log or copies of it exist.
If one of your friends deletes a file from a drive that you shared,
the file is still there and can be recovered: _SSB Drive_ is "time
machine-ready" in the sense that all information is available, just
that this PoC does not yet implement a method to browse a drive's
history (and a method to resurrect old entries).

Have fun and handle your friends' SSB drives with respect!

cft, Aug 2018

---

## Example CLI sessions

The full signature of the _SSB Drive_ app is:

```txt
$ ./ssb-drive.py [options] [UUID]
where options are:
  -h, --help        show this help message and exit
  -del              delete the given drive
  -list             list all active drives
  -new              create new drive
  -peer IP:PORT:ID  remote's ip:port:id (default is localhost:8008:default_id
  -port PORT        local port (i.e. become a server)
  -tty              run in line mode (instead of fullscreen terminal)
  -user USERNAME    username (default is ~/.ssb user, or ~/.ssb/user.USERNAME)
  -udel             undelete the given drive
UUID                ssb-drive's uuid (default is youngest drive)
```

### Experimenting with SSB Drive and/or testing local developments

In order to perform local experiments with the SSB Drive Protocol, it
is possible **and advised** to run with local SSB users rather than
your own ID. To this end, for each user USERNAME, we keep a
subdirectory with the following format:

```txt
~/.ssb/user.USERNAME
```

and populate it with the standard SSB data. The _SSB Drive_ software
offers an easy way to create new users as follows:

```txt
# LOCAL DEMO STEPS 1

$ ./ssb/local/config.py -list
default user:
  @AiBJDta+4boyh2USNGwIagH/wKjeruTcDX2Aj1r/haM=.ed25519
local users:

$ ./ssb/local/config.py -new Alice
** new user Alice (@C8pPydEHuGxCjFUYBLmBOGTIPkYQeZ3FnKvQTvT0MDk=.ed25519)
$ ./ssb/local/config.py -new Bob
** new user Bob (@ihS4TZa55eMjjWOC5oN+oF9GTvc23GQcGyt0xqJ1XD0=.ed25519)

$ ./ssb/local/config.py -list
default user:
  @AiBJDta+4boyh2USNGwIagH/wKjeruTcDX2Aj1r/haM=.ed25519
local users:
  @C8pPydEHuGxCjFUYBLmBOGTIPkYQeZ3FnKvQTvT0MDk=.ed25519  Alice
  @ihS4TZa55eMjjWOC5oN+oF9GTvc23GQcGyt0xqJ1XD0=.ed25519  Bob
```

Because peers only retrieve each other's logs if they follow each
other, we have to populate the `friends.json` file for both, see below
how this is done. Once this is established, we will (i) create a
drive on Alice's side, (ii) let Bob sync with Alice's content, and
(iii) start also Bob's _SSB Drive_ client:

```txt
# LOCAL DEMO STEPS 2

$ ./ssb/local/config.py -friends Alice Bob
** friend records updated

$ ./ssb-drive.py -user Alice -new
** new drive created, uuid=9dfc8124-6a6b-5730-9c04-5eed67ac770e

# start Alice's client in one terminal window:
$ ./ssb-drive.py -user Alice -port 7007
...

# in another terminal window, let Bob sync up:
$ ./ssb-drive.py -user Bob -sync -peer localhost:7007:ID_OF_ALICE
...

# and start his SSB Drive client:
$ ./ssb-drive.py -user Bob -peer localhost:7007:ID_OF_ALICE
```

It is also possible to run the _SSB Drive_ app in line mode by
selecting the `-tty` option. Note however that this mode does not
yet support peer connections i.e., you will work on the given
user's log __as if offline__:

```txt
$ ./ssb-drive.py -user Alice -tty
Secure Scuttlebutt Drive client (v2018-08-21).  Type ? for help.
running in unencrypted mode

drv=9dfc8124-6a6b-5730-9c04-5eed67ac770e (2018-08-22 21:44:21)
cwd=/
ssb_drv> help

Documented commands (type help <topic>):
========================================
cat  cd  exit  get  help  ls  mkdir  put  pwd  rm  rmdir  stat  sync  tree

ssb_drv> tree
.
'-- dir1/
    |-- README.md
    '-- dir2/
ssb_drv> exit
```

---

## Technical Details

### The "SSB Drive Protocol" (SDP)

to be written

### Todo

* "encrypted SSB Drive": adapt the tangles and let them run in the private log
* implement a time machine (browse history, enable resurrecting files)
* think about mounting other drives into a drive's name tree
* run -tty mode with asyncio and serve the peer protocol in the background

----
