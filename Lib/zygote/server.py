# -*- coding: utf-8 -*-
from __future__ import absolute_import

import code
import contextlib
import errno
import fcntl
import logging
import os
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

MAGIC = 'zygote425f637d16cb47008223fbc983fdce61'


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


class ZygoteBase(object):

    exchanged_fds = ()
    forwarded_signals = ()

    def __init__(self, path):
        super(ZygoteBase, self).__init__()
        self.path = path
        self.original_pid = os.getpid()
        self.original_stderr = os.fdopen(os.dup(2), 'w', 0)

    def set_conn(self, conn):
        self.conn = conn
        self.input = conn.makefile('rb', -1)
        self.output = conn.makefile('wb', 0)

    def write(self, buf):
        self.output.write(struct.pack('L', len(buf)))
        self.output.write(buf)

    def read(self):
        [buflen] = struct.unpack('L', self.input.read(struct.calcsize('L')))
        return self.input.read(buflen)

    def writeobj(self, buf):
        self.write(pickle.dumps(buf))

    def readobj(self):
        return pickle.loads(self.read())

    def exchange_magic(self, conn):
        conn.send(MAGIC)
        their_magic = conn.recv(len(MAGIC))
        return their_magic == MAGIC

    def setup_deathpact_as(self, as_server):
        page_size = resource.getpagesize()
        tmpdir = tempfile.mkdtemp()
        my_filename = os.path.join(tmpdir, 'deathpact-%d' % (os.getpid(),))
        os.mkfifo(my_filename)
        my_r = os.open(my_filename, os.O_RDONLY | os.O_NONBLOCK)
        fcntl.fcntl(my_r, fcntl.F_SETPIPE_SZ, page_size)

        if as_server:
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

        threading.Thread(target=wait, name='deathpact').start()


class ZygoteServer(ZygoteBase):

    DEFAULT_REAP_INTERVAL = 3

    def __init__(self, path, daemonize=False, reap_interval=DEFAULT_REAP_INTERVAL):
        super(ZygoteServer, self).__init__(path)
        self.daemonize = daemonize
        self.reap_interval = reap_interval
        self.child_pids = set()
        self.last_reap = 0

    def setup_deathpact(self):
        self.setup_deathpact_as(True)

    def init(self):
        pass

    def work(self):
        pass

    def reap(self):
        for pid in list(self.child_pids):
            rpid, rc = os.waitpid(pid, os.WNOHANG)
            if rpid:
                self.child_pids.remove(pid)
                log.info('Reaped :: pid: %d, rc: %d' % (pid, rc))

    def maybe_reap(self):
        if time.time() - self.last_reap < self.reap_interval:
            return
        self.reap()
        self.last_reap = time.time()
            
    def run(self):
        if os.path.exists(self.path):
            raise ValueError(self.path, 'File already exists')

        log.info('Initializing')
        self.init()

        log.info('Binding :: path: %s' % (self.path,))
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)

        self.sock.listen(1)
        log.info('Listening')

        while True:
            if not self.daemonize:
                self.maybe_reap()
                self.sock.settimeout(self.reap_interval)
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout:
                    continue
            else:
                conn, addr = self.sock.accept()
            log.info('Connection :: pid: %d, uid: %d, gid %d' % get_sock_cred(conn))
            self.handle_conn(conn)

        if not self.daemonize:
            self.reap()

    def handle_conn(self, conn):
        if not self.exchange_magic(conn):
            conn.close()
            log.error('Rejected')
            return

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

        log.info('Serving')

        try:
            with contextlib.closing(conn):
                self.set_conn(conn)
                self.handshake()
                self.work()
                log.debug('Complete')
            os._exit(0)
        except Exception:
            log.info('Exception: %s' % format_last_ex())
            os._exit(1)

    def handshake(self):
        self.client_pid = get_sock_cred(self.conn)[0]
        for fd in self.exchanged_fds:
            ret, data = passfd.recvfd(self.conn.fileno())
            if ret < 0:
                raise ValueError(ret)
            os.dup2(ret, fd)
        self.write(str(os.getpid()))


class ZygoteConnectionRefusedException(Exception):
    pass


class ZygoteClient(ZygoteBase):

    def run(self):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        conn.connect(self.path)

        self.handle_conn(conn)

    def setup_deathpact(self):
        self.setup_deathpact_as(False)

    def work(self):
        pass

    def handle_conn(self, conn):
        with contextlib.closing(conn):
            if not self.exchange_magic(conn):
                raise ZygoteConnectionRefusedException()
            self.set_conn(conn)
            self.handshake()
            self.install_signal_handlers()
            self.work()

    def handshake(self):
        for fd in self.exchanged_fds:
            ret = passfd.sendfd(self.conn.fileno(), fd)
            if ret < 0:
                raise ValueError(ret)
        self.server_pid = self.read()

    def install_signal_handlers(self):
        def handler(num, frame):
            os.kill(self.server_pid, num)

        for num in self.forwarded_signals:
            try:
                signal.signal(num, handler)
            except Exception as e:
                pass


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

    def handshake(self):
        super(InteractiveZygoteClient, self).handshake()
        self.setup_deathpact()

    def work(self):
        while True:
            signal.pause()  # lel


def main():
    logging.basicConfig(level=logging.INFO)

    import optparse

    option_parser = optparse.OptionParser(add_help_option=False, usage='usage: %prog path')
    option_parser.add_option('-s', '--server', dest='is_server', action='store_true')
    option_parser.add_option('-d', '--daemon', dest='is_daemon', action='store_true')

    options, args = option_parser.parse_args()
    if len(args) != 1:
        option_parser.error('invalid arguments')
    path, = args

    if options.is_server:
        InteractiveZygoteServer(path, daemonize=options.is_daemon).run()
    else:
        InteractiveZygoteClient(path).run()


if __name__ == '__main__':
    main()
