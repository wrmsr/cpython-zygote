# -*- coding: utf-8 -*-
from __future__ import absolute_import

import contextlib
import logging
import os
import signal
import socket
import struct
import sys
import traceback


log = logging.getLogger(__name__)


def format_last_ex():
    exc, msc, tb = sys.exc_info()
    return 'Exception: %s\nExceptionMsg: %s\n%s\n' % (
        repr(exc), msc, ''.join(traceback.format_tb(tb)))

def open_conn_files(conn):
    return conn.makefile('rb', -1), conn.makefile('wb', 0)

def get_sock_cred(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', creds)
    return pid, uid, gid


class ZygoteBase(object):

    exchanged_fds = (0, 1, 2)
    forwarded_signals = [getattr(signal, name) for name in dir(signal)
        if name.startswith('SIG')]

    def __init__(self, path):
        self.path = path
        self.original_pid = os.getpid()
        self.stderr = os.fdopen(os.dup(2), 'w', 0)

    def set_conn(self, conn):
        self.conn = conn
        self.input, self.output = open_conn_files(self.conn)


class ZygoteServer(ZygoteBase):

    def init(self):
        pass

    def work(self):
        pass

    def __call__(self):
        if os.path.exists(self.path):
            raise ValueError(self.path, 'File already exists')

        log.info('Initializing')
        self.init()

        log.info('Binding :: path: %s' % self.path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)

        self.sock.listen(1)
        log.info('Listening')

        while True:
            conn, addr = self.sock.accept()
            log.info('Connection :: pid: %d, uid: %d, gid %d' % get_sock_cred(conn))
            self.handle_conn(conn)

    def handle_conn(self, conn):
        fork_pid = os.fork()
        if fork_pid:
            log.info('Forked(1) :: pid: %d' % (fork_pid))
            conn.close()
            os.waitpid(fork_pid, 0)
            log.info('Forked(1) done :: pid: %d' % (fork_pid))
            return

        fork_pid = os.fork()
        if fork_pid:
            log.info('Forked(2) :: pid: %d' % (fork_pid))
            os._exit(0)

        log.info('Serving')

        try:
            with contextlib.closing(conn):
                self.set_conn(conn)
                self.handshake()
                self.work()
                log.info('Complete')
            os._exit(0)
        except Exception:
            log.info('Exception: %s' % format_last_ex())
            os._exit(1)

    def handshake(self):
        self.client_pid = get_sock_cred(self.conn)[0]
        for fd in self.exchanged_fds:
            ret, data = recvfd(self.conn.fileno())
            if ret < 0:
                raise ValueError(ret)
            os.dup2(ret, fd)
        self.out.write('%d\n' % os.getpid())


class ZygoteClient(ZygoteBase):

    def __call__(self):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        conn.connect(self.path)

        self.handle_conn(conn)

    def handle_conn(self, conn):
        with contextlib.closing(conn):
            self.set_conn(conn)
            self.handshake()
            self.install_signal_handlers()

            while True:
                line = self.input.readline()
                if not line:
                    break

    def handshake(self):
        for fd in self.exchanged_fds:
            ret = sendfd(self.conn.fileno(), fd)
            if ret < 0:
                raise ValueError(ret)
        self.server_pid = int(self.input.readline())

    def install_signal_handlers(self):
        def handler(num, frame):
            os.kill(self.server_pid, num)

        for num in self.forwarded_signals:
            try:
                signal.signal(num, handler)
            except Exception as e:
                pass
