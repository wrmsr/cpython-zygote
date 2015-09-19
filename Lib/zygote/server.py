# -*- coding: utf-8 -*-
from __future__ import absolute_import

import abc
import cStringIO
import code
import contextlib
import ctypes
import errno
import fcntl
import logging
import optparse
import os
import os
import pickle
import resource
import signal
import socket
import struct
import sys
import tempfile
import threading
import time
import traceback

from . import passfd

try:
    import cPickle as pickle
except ImportError:
    import pickle


log = logging.getLogger(__name__)


try:
    import setproctitle as setproctitle_module
except ImportError:
    def getproctitle():
        return None

    def setproctitle(s):
        pass
else:
    getproctitle = setproctitle_module.getproctitle
    setproctitle = setproctitle_module.setproctitle


if not hasattr(fcntl, 'F_SETPIPE_SZ'):
    import platform
    if platform.system() == 'Linux':
        fcntl.F_SETPIPE_SZ = 1031


def format_last_ex():
    exc, msc, tb = sys.exc_info()
    return 'Exception: %s\nExceptionMsg: %s\n%s\n' % (
        repr(exc), msc, ''.join(traceback.format_tb(tb)))

def get_sock_cred(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', creds)
    return pid, uid, gid


RLIMIT_RESOURCES = dict((getattr(resource, k), k) for k in (
    'RLIMIT_CPU',
    'RLIMIT_FSIZE',
    'RLIMIT_DATA',
    'RLIMIT_STACK',
    'RLIMIT_CORE',
    'RLIMIT_NOFILE',
    'RLIMIT_OFILE',
    # 'RLIMIT_VMEM',
    'RLIMIT_AS',
    'RLIMIT_RSS',
    'RLIMIT_NPROC',
    'RLIMIT_MEMLOCK',
    # 'RLIMIT_SBSIZE',
))


class ZygoteBase(object):
    __metaclass__ = abc.ABCMeta

    MAGIC = 'zygote-425f637d16cb47008223fbc983fdce61'

    def __init__(
            self,
            path,
            deathsig=(),
            deathwatch_path=None,
            deathpact=False,
            forwarded_signals=(),
            exchanged_fds=(),
            inherited_rlimits=(),
    ):
        super(ZygoteBase, self).__init__()

        self.path = path
        self.deathsig = deathsig
        self.deathwatch_path = deathwatch_path
        if deathpact == 'either':
            self.deathpact = 'either'
        elif deathpact == 'true' or deathpact is True:
            self.deathpact = 'true'
        elif deathpact == 'false' or deathpact is False:
            self.deathpact = 'false'
        else:
            raise TypeError(deathpact)
        self.forwarded_signals = forwarded_signals
        self.inherited_rlimits = inherited_rlimits
        self.exchanged_fds = exchanged_fds

        self.unique_path = None
        self.conn = None
        self.remote_pid = None
        self.deathwatch_pid = None

        self.original_pid = os.getpid()
        self.original_stderr = os.fdopen(os.dup(2), 'w', 0)
        self.original_proctitle = getproctitle()

    @abc.abstractproperty
    def is_server(self):
        raise NotImplementedError()

    def new_client(self):
        if self.unique_path is None:
            raise TypeError()
        return ZygoteClient(
            self.unique_path,
            deathpact='either'
        )

    def exchange_magic(self, conn):
        conn.send(self.MAGIC)
        their_magic = conn.recv(len(self.MAGIC))
        return their_magic == self.MAGIC

    def set_conn(self, conn):
        if self.conn is not None:
            raise TypeError(self.conn)
        self.conn = conn
        self.input = conn.makefile('rb', -1)
        self.output = conn.makefile('wb', 0)

    def writelong(self, l):
        self.output.write(struct.pack('L', l))

    def readlong(self):
        sz = struct.calcsize('L')
        buf = self.input.read(sz)
        if len(buf) != sz:
            raise TypeError('Read error: expected %d, got %d' % (sz, len(buf)))
        [l] = struct.unpack('L', buf)
        return l

    def write(self, buf):
        self.writelong(len(buf))
        self.output.write(buf)

    def read(self):
        sz = self.readlong()
        buf = self.input.read(sz)
        if len(buf) != sz:
            raise TypeError('Read error: expected %d, got %d' % (sz, len(buf)))
        return buf

    def writeobj(self, obj):
        self.write(pickle.dumps(obj))

    def readobj(self):
        return pickle.loads(self.read())

    def writeobjseq(self, seq, obj):
        self.output.write(struct.pack('L', seq))
        self.write(pickle.dumps(obj))

    def readobjseq(self):
        [seq] = struct.unpack('L', self.input.read(struct.calcsize('L')))
        return seq, pickle.loads(self.read())

    def handshake(self, conn):
        self.set_conn(conn)
        self.setup_deathsig()
        self.setup_deathwatch()
        self.setup_remote_pid()
        self.setup_deathpact()
        self.setup_forwarded_signals()
        self.setup_rlimits()
        self.setup_unique_path()
        self.setup_exchanged_fds()

    def setup_deathsig(self):
        if self.deathsig is not None:
            libc.prctl(libc.PR_SET_PDEATHSIG, self.deathsig, 0, 0, 0, 0)

    def setup_deathwatch(self):
        if not self.deathwatch_path:
            return
        if self.deathwatch_pid is not None:
            raise TypeError()

        f = open(self.deathwatch_path, 'rb')
        fork_pid = os.fork()
        if fork_pid:
            self.deathwatch_pid = fork_pid
            return

        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass
        log.debug('Deathwatch fired')
        os._exit(0)
        raise RuntimeError('unreachable')

    def check_deathwatch(self):
        if self.deathwatch_pid is not None:
            rpid, rc = os.waitpid(self.deathwatch_pid, os.WNOHANG)
            if rpid:
                log.info('Deathwatch fired :: pid: %d, rc: %d' % (self.deathwatch_pid, rc))
                os._exit(0)
                raise RuntimeError('unreachable')

    def setup_remote_pid(self):
        if self.is_server:
            self.remote_pid = get_sock_cred(self.conn)[0]
            self.write(str(os.getpid()))
        else:
            self.remote_pid = int(self.read())

    def setup_deathpact(self):
        if self.is_server:
            theirs = self.read()
            self.write(self.deathpact)
        else:
            self.write(self.deathpact)
            theirs = self.read()

        if theirs == 'false':
            if self.deathpact == 'true':
                raise TypeError('Deathpact mismatch: %r vs %r' % (self.deathpact, theirs))
            return
        elif theirs == 'true':
            if self.deathpact not in ('true', 'either'):
                raise TypeError('Deathpact mismatch: %r vs %r' % (self.deathpact, theirs))
        else:
            raise TypeError('Unknown deathpact type: %r' % (theirs,))

        page_size = resource.getpagesize()
        tmpdir = tempfile.mkdtemp()
        my_filename = os.path.join(tmpdir, 'deathpact-%d' % (os.getpid(),))
        os.mkfifo(my_filename)
        my_r = os.open(my_filename, os.O_RDONLY | os.O_NONBLOCK)
        fcntl.fcntl(my_r, fcntl.F_SETPIPE_SZ, page_size)

        if self.is_server:
            their_filename = self.read()
            their_w = os.open(their_filename, os.O_WRONLY)
            self.write(my_filename)
            self.read()
        else:
            self.write(my_filename)
            their_filename = self.read()
            their_w = os.open(their_filename, os.O_WRONLY)
            self.write('')

        fcntl.fcntl(their_w, fcntl.F_SETPIPE_SZ, page_size)
        os.unlink(my_filename)
        os.rmdir(tmpdir)

        def wait():
            while True:
                try:
                    os.write(their_w, '\0' * page_size)
                except OSError as e:
                    if e.errno == errno.EPIPE:
                        break
            log.debug('Deathpact fired')
            os._exit(0)
            raise RuntimeError('unreachable')

        thread = threading.Thread(target=wait, name='deathpact')
        thread.daemon = True
        thread.start()

    def setup_forwarded_signals(self):
        def handler(num, frame):
            os.kill(self.remote_pid, num)
        for num in self.forwarded_signals:
            try:
                signal.signal(num, handler)
            except Exception:
                pass

    def setup_rlimits(self):
        if self.is_server:
            rlimits = self.readobj()
            for i in self.inherited_rlimits:
                resource.setrlimit(i, rlimits[i])
        else:
            rlimits = dict((i, resource.getrlimit(i)) for i in RLIMIT_RESOURCES.keys())
            self.writeobj(rlimits)

    def setup_unique_path(self):
        if self.is_server:
            if not os.path.exists(self.unique_path):
                raise EnvironmentError(self.unique_path)
            self.write(self.unique_path)
        else:
            self.unique_path = self.read()
            if not os.path.exists(self.unique_path):
                raise EnvironmentError(self.unique_path)

    def setup_exchanged_fds(self):
        FIXME

        self.client_pid = get_sock_cred(self.conn)[0]
        for fd in self.exchanged_fds:
            ret, data = passfd.recvfd(self.conn.fileno())
            if ret < 0:
                raise ValueError(ret)
            os.dup2(ret, fd)
        self.write(str(os.getpid()))

        for fd in self.exchanged_fds:
            ret = passfd.sendfd(self.conn.fileno(), fd)
            if ret < 0:
                raise ValueError(ret)
        self.server_pid = self.read()


class ZygoteServer(ZygoteBase):

    DEFAULT_THINK_INTERVAL = 3

    def __init__(
            self,
            path,
            **kwargs
    ):
        self.override = kwargs.pop('override', False)
        self.daemonize = kwargs.pop('daemonize', False)
        self.think_interval = kwargs.pop('think_interval', self.DEFAULT_THINK_INTERVAL)
        self.idle_shutdown_interval = kwargs.pop('idle_shutdown_interval', None)
        self.autostart_lock_fd = kwargs.pop('autostart_lock_fd', None)

        super(ZygoteServer, self).__init__(path, **kwargs)
        if self.daemonize and (self.deathsig is not None):
            raise TypeError()

        self.inode = None
        self.child_pids = set()
        self.last_think = 0
        self.last_activity = 0

    @property
    def is_server(self):
        return True

    def warmup(self):
        if self.conn is not None:
            raise TypeError('Already connected')

    @abc.abstractmethod
    def serve(self):
        raise NotImplementedError()

    def think(self):
        self.check_deathwatch()

        for pid in list(self.child_pids):
            rpid, rc = os.waitpid(pid, os.WNOHANG)
            if rpid:
                self.child_pids.remove(pid)
                log.info('Reaped :: pid: %d, rc: %d' % (pid, rc))

        if self.idle_shutdown_interval and not self.child_pids:
            if time.time() - self.last_activity >= self.idle_shutdown_interval:
                log.info('Idle shutdown fired')
                os._exit(0)
                raise RuntimeError('unreachable')

    def maybe_think(self):
        if time.time() - self.last_think >= self.think_interval:
            self.think()
            self.last_think = time.time()

    def run(self):
        unique_directory = tempfile.mkdtemp(prefix='zygote-%d-' % (os.getpid(),))
        self.unique_path = os.path.join(unique_directory, 'zygote.sock')

        log.info('Binding :: path: %s' % (self.unique_path,))
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.unique_path)

        log.info('Bound :: path: %s' % (self.path,))
        self.inode = os.stat(self.unique_path).st_ino
        log.info('Bound :: inode: %d' % (self.inode,))

        if self.override:
            try:
                os.unlink(self.path)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    log.info('Overrode :: path: %s' % (self.path,))
                else:
                    raise
            else:
                log.info('Override unnecessary :: path: %s' % (self.path,))

        log.info('Linking :: path: %s' % (self.path,))
        os.symlink(self.unique_path, self.path)
        log.info('Linked :: path: %s' % (self.path,))

        log.info('Warmup')
        self.warmup()

        if len(threading.enumerate()) != 1:
            log.warn('Multiple active threads detected')

        self.sock.listen(1)
        log.info('Listening')

        if self.autostart_lock_fd is not None:
            log.info('Releasing autostart lock :: fd: %d' % (self.autostart_lock_fd,))
            os.close(self.autostart_lock_fd)

        self.running = True
        self.last_activity = time.time()
        while self.running:
            self.maybe_think()
            self.sock.settimeout(self.think_interval)
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            log.info('Connection :: pid: %d, uid: %d, gid %d' % get_sock_cred(conn))
            self.handle_conn(conn)
            self.last_activity = time.time()

        log.info('Awaiting child termination')
        while self.child_pids:
            self.maybe_think()
            time.sleep(self.think_interval)

        log.info('Done')
        os._exit(0)
        raise RuntimeError('Unreachable')

    def handle_conn(self, conn):
        if not self.exchange_magic(conn):
            conn.close()
            log.error('Rejected')
            return

        cmd = conn.recv(4)
        if cmd == 'fork':
            self.handle_fork(conn)
        elif cmd == 'stop':
            self.handle_stop(conn)
        elif cmd == 'kill':
            self.handle_kill(conn)
        else:
            conn.close()
            log.error('Unknown command :: %s' % (cmd,))

    def handle_fork(self, conn):
        original_pid = os.getpid()
        fork_pid = os.fork()
        if fork_pid:
            log.info('Forked(1) :: pid: %d' % (fork_pid,))
            conn.close()
            if self.daemonize:
                os.waitpid(fork_pid, 0)
            else:
                self.child_pids.add(fork_pid)
            log.info('Forked(1) done :: pid: %d' % (fork_pid,))
            return

        if self.daemonize:
            fork_pid = os.fork()
            if fork_pid:
                log.info('Forked(2) :: pid: %d' % (fork_pid,))
                os._exit(0)
                raise RuntimeError('unreachable')

        log.info('Serving')
        try:
            with contextlib.closing(conn):
                self.handshake(conn)
                setproctitle('(zygote child (%d -> %d))' % (original_pid, self.remote_pid))
                self.serve()
                log.debug('Complete')
            os._exit(0)
        except Exception:
            log.info('Exception: %s' % format_last_ex())
            os._exit(1)
        raise RuntimeError('unreachable')

    def handle_stop(self, conn):
        if self.running:
            log.info('Stopping by request')
            self.running = False
            os.unlink(self.unique_path)
            log.info('Removed :: path: %s' % (self.unique_path,))
        else:
            log.info('Redundant stop requested')

    def handle_kill(self, conn):
        log.info('Exiting by request')
        os._exit(0)
        raise RuntimeError('Unreachable')


class ZygoteConnectionRefusedException(Exception):
    pass


class ZygoteClient(ZygoteBase):

    DEFAULT_AUTOSTART_TIMEOUT = 60
    DEFAULT_AUTOSTART_SLEEP = 0.1

    def __init__(
            self,
            path,
            **kwargs
    ):
        self.autostart = kwargs.pop('autostart', None)
        self.autostart_lock_path = kwargs.pop('autostart_lock_path', None)
        self.autostart_timeout = kwargs.pop('autostart_timeout', self.DEFAULT_AUTOSTART_TIMEOUT)
        self.autostart_sleep = kwargs.pop('autostart_sleep', self.DEFAULT_AUTOSTART_SLEEP)
        self.autostart_daemonize = kwargs.pop('autostart_daemonize', True)
        super(ZygoteClient, self).__init__(path, **kwargs)
        self.autostart_pid = None

    @property
    def is_server(self):
        return False

    def connect(self):
        if self.autostart is None:
            return self._connect()

        conn = self.try_connect()
        if conn is not None:
            return conn

        lock_fd = None
        if self.autostart_lock_path is not None:
            log.info('Acquiring autostart lock :: %s' % (self.autostart_lock_path,))

            lock_fd = os.open(self.autostart_lock_path, os.O_CREAT | os.O_RDWR)

            end = time.time() + self.autostart_timeout
            while time.time() < end:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except IOError as e:
                    if e.errno != errno.EAGAIN:
                        raise
                else:
                    break
                time.sleep(self.autostart_sleep)

            if lock_fd is None:
                log.info('Failed to acquire autostart lock :: %s' % (self.autostart_lock_path,))
                return self._connect()

        try:
            if lock_fd is not None:
                log.info('Acquired autostart lock :: %s' % (self.autostart_lock_path,))

            conn = self.try_connect()
            if conn is not None:
                log.info('Autostart unnecessary')
                return conn

            if len(threading.enumerate()) != 1:
                log.warn('Multiple active threads detected')

            original_pid = os.getpid()
            pid = os.fork()
            if pid:
                log.info('Autostart forked(1) :: pid: %d' % (pid,))
                self.autostart_pid = pid
                if self.autostart_daemonize:
                    os.waitpid(pid, 0)

                end = time.time() + self.autostart_timeout
                while time.time() < end:
                    conn = self.try_connect()
                    if conn is not None:
                        return conn
                    time.sleep(self.autostart_sleep)

                log.info('Autostart timeout')
                return self._connect()

            if self.autostart_daemonize:
                fork_pid = os.fork()
                if fork_pid:
                    log.info('Autostart forked(2) :: pid: %d' % (fork_pid,))
                    os._exit(0)
                    raise RuntimeError('unreachable')

            log.info('Autostarting')

            setproctitle('(zygote autostart (%d))' % (original_pid,))

            self.autostart(lock_fd)

        finally:
            if lock_fd is not None:
                os.close(lock_fd)
                log.info('Released autostart lock :: %s' % (self.autostart_lock_path,))

        raise RuntimeError('unreachable')

    def try_connect(self):
        try:
            return self._connect()
        except socket.error as e:
            if e.errno in (errno.ENOENT, errno.ECONNREFUSED):
                return None
            raise

    def _connect(self):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        conn.connect(self.path)
        if not self.exchange_magic(conn):
            raise ZygoteConnectionRefusedException()
        return conn

    def fork(self):
        if self.conn is not None:
            raise TypeError()
        conn = self.connect()
        conn.send('fork')
        self.handshake(conn)

    def command(self, cmd):
        with contextlib.closing(self.connect()) as conn:
            conn.send(cmd)

    def try_command(self, cmd):
        conn = self.try_connect()
        if conn is None:
            return False
        with contextlib.closing(conn):
            conn.send(cmd)
        return True

    def stop(self):
        self.command('stop')

    def kill(self):
        self.command('kill')

    def try_stop(self):
        self.try_command('stop')

    def try_kill(self):
        self.try_command('kill')


class InteractiveZygoteBase(object):

    exchanged_fds = ZygoteBase.exchanged_fds + (0, 1, 2)
    forwarded_signals = ZygoteBase.forwarded_signals + tuple(
        getattr(signal, name) for name in dir(signal) if name.startswith('SIG'))


class InteractiveZygoteServer(InteractiveZygoteBase, ZygoteServer):

    def __init__(self, path, init=None, try_ipython=True, **kwargs):
        super(InteractiveZygoteServer, self).__init__(path, **kwargs)
        self.try_ipython = try_ipython
        self.init_fn = init

    def init(self):
        super(InteractiveZygoteServer, self).init()
        if self.init_fn is not None:
            self.init_fn()

    def handshake(self):
        super(InteractiveZygoteServer, self).handshake()
        self.setup_deathpact()

    def work(self):
        cmd = self.read()
        if cmd:
            exec cmd in globals(), globals()
            return

        if self.try_ipython:
            try:
                import IPython
            except ImportError:
                pass
            else:
                vers = tuple(map(int, IPython.__version__.split('.')))
                if vers[0] <= 0 and vers[1] <= 11:
                    from IPython.Shell import IPShellEmbed
                    ipshell = IPShellEmbed()
                    ipshell()
                else:
                    IPython.embed()
                return

        code.InteractiveConsole(locals=globals()).interact()


class InteractiveZygoteClient(InteractiveZygoteBase, ZygoteClient):

    def __init__(self, path, cmd=None, **kwargs):
        super(InteractiveZygoteClient, self).__init__(path, **kwargs)
        self.cmd = cmd

    def handshake(self):
        super(InteractiveZygoteClient, self).handshake()
        self.setup_deathpact()

    def work(self):
        self.write(self.cmd or '')
        while True:
            signal.pause()  # lel


def main():
    import optparse

    option_parser = optparse.OptionParser(add_help_option=False, usage='usage: %prog path')
    option_parser.add_option('-s', '--server', dest='is_server', action='store_true')
    option_parser.add_option('-d', '--daemon', dest='is_daemon', action='store_true')
    option_parser.add_option('-t', '--ipython', dest='is_ipython', action='store_true')
    option_parser.add_option('-v', '--verbose', dest='is_verbose', action='store_true')
    option_parser.add_option('-c', '--cmd', dest='cmd')

    options, args = option_parser.parse_args()
    if len(args) != 1:
        option_parser.error('invalid arguments')
    path, = args

    if options.is_verbose:
        logging.basicConfig(level=logging.INFO)

    if options.is_server:
        def init():
            if options.cmd:
                exec options.cmd in globals(), globals()
        InteractiveZygoteServer(path, daemonize=options.is_daemon, init=init, try_ipython=options.is_ipython).run()
    else:
        InteractiveZygoteClient(path, cmd=options.cmd).run()


if __name__ == '__main__':
    main()
