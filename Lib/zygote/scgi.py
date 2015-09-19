"""
# Copyright (c) 2005, 2006 Allan Saddi <allan@saddi.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id: scgi_base.py 2306 2007-01-02 22:15:53Z asaddi $

TODO:
- uwsgi protocol subclass

scgi - an SCGI/WSGI gateway.

For more information about SCGI and mod_scgi for Apache1/Apache2, see
<http://www.mems-exchange.org/software/scgi/>.

For more information about the Web Server Gateway Interface, see
<http://www.python.org/peps/pep-0333.html>.

Example usage:

  #!/usr/bin/env python
  import sys
  from myapplication import app # Assume app is your WSGI application object
  from scgi import WSGIServer
  ret = WSGIServer(app).run()
  sys.exit(ret and 42 or 0)

See the documentation for WSGIServer for more information.

About the bit of logic at the end:
Upon receiving SIGHUP, the python script will exit with status code 42. This
can be used by a wrapper script to determine if the python script should be
re-run. When a SIGINT or SIGTERM is received, the script exits with status
code 0, possibly indicating a normal exit.

Example wrapper script:

  #!/bin/sh
  STATUS=42
  while test $STATUS -eq 42; do
    python "$@" that_script_above.py
    STATUS=$?
  done
"""
from __future__ import absolute_import

import datetime
import errno
import io as StringIO
import logging
import os
import select
import signal
import socket
import sys
import time
import warnings


log = logging.getLogger(__name__)


class NoDefault(object):
    pass


class ProtocolError(Exception):
    pass


def recvall(sock, length):
    dataList = []
    recvLen = 0
    while length:
        try:
            data = sock.recv(length)
        except socket.error as e:
            if e[0] == errno.EAGAIN:
                select.select([sock], [], [])
                continue
            else:
                raise
        if not data: # EOF
            break
        dataList.append(data)
        dataLen = len(data)
        recvLen += dataLen
        length -= dataLen
    return ''.join(dataList), recvLen


def read_netstring(sock):
    size = ''
    while True:
        try:
            c = sock.recv(1)
        except socket.error as e:
            if e[0] == errno.EAGAIN:
                select.select([sock], [], [])
                continue
            else:
                raise
        if c == ':':
            break
        if not c:
            raise EOFError
        size += c

    try:
        size = int(size)
        if size < 0:
            raise ValueError
    except ValueError:
        raise ProtocolError('invalid netstring length')
    s, length = recvall(sock, size)
    if length < size:
        raise EOFError

    trailer, length = recvall(sock, 1)
    if length < 1:
        raise EOFError
    if trailer != ',':
        raise ProtocolError('invalid netstring trailer')
    return s


class StdoutWrapper(object):

    def __init__(self, file):
        super(StdoutWrapper, self).__init__()
        self._file = file
        self._data_written = False

    def write(self, data):
        if data:
            self._data_written = True
        self._file.write(data)

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def __getattr__(self, name):
        return getattr(self._file, name)


class Request(object):

    def __init__(self, conn, environ, input, output):
        super(Request, self).__init__()
        self.conn = conn
        self.environ = environ
        self.stdin = input
        self.stdout = StdoutWrapper(output)

    def run(self):
        log.info(
            '%s %s%s',
            self.environ['REQUEST_METHOD'],
            self.environ.get('SCRIPT_NAME', ''),
            self.environ.get('PATH_INFO', ''))

        start = time.time()
        try:
            self.conn.server.handler(self)
        except:
            log.exception('Exception caught from handler')
            if not self.stdout.dataWritten:
                self.conn.server.error(self)
        end = time.time()

        handler_time = end - start
        log.debug(
            '%s %s%s done (%.3f secs)',
            self.environ['REQUEST_METHOD'],
            self.environ.get('SCRIPT_NAME', ''),
            self.environ.get('PATH_INFO', ''),
            handler_time)


class Connection(object):

    def __init__(self, sock, addr, server):
        super(Connection, self).__init__()
        self.sock = sock
        self.addr = addr
        self.server = server

    def run(self):
        if len(self._addr) == 2:
            log.debug('Connection starting up (%s:%d)', self._addr[0], self._addr[1])
        try:
            self.process_input()
        except (EOFError, KeyboardInterrupt):
            pass
        except ProtocolError as e:
            log.error("Protocol error '%s'", str(e))
        except:
            log.exception('Exception caught in Connection')
        if len(self._addr) == 2:
            log.debug('Connection shutting down (%s:%d)', self._addr[0], self._addr[1])
        self.sock.close()

    def process_input(self):
        headers = read_netstring(self.sock)
        headers = headers.split('\x00')[:-1]
        if len(headers) % 2 != 0:
            raise ProtocolError('invalid headers')
        environ = {}
        for i in range(len(headers) / 2):
            environ[headers[2*i]] = headers[2*i+1]

        clen = environ.get('CONTENT_LENGTH')
        if clen is None:
            raise ProtocolError('missing CONTENT_LENGTH')
        try:
            clen = int(clen)
            if clen < 0:
                raise ValueError
        except ValueError:
            raise ProtocolError('invalid CONTENT_LENGTH')

        self.sock.setblocking(1)
        if clen:
            input = self.sock.makefile('r')
        else:
            input = StringIO.StringIO()

        output = self.sock.makefile('w')
        req = Request(self, environ, input, output)
        req.run()
        output.close()
        input.close()


class BaseSCGIServer(object):

    REQUEST_CLASS = Request

    def __init__(
            self,
            application,
            script_name=NoDefault,
            environ=None,
            multithreaded=True,
            multiprocess=False,
            bind_address=('localhost', 4000),
            umask=None,
            debug=True
    ):
        if environ is None:
            environ = {}

        self.application = application
        self.script_name = script_name
        self.environ = environ
        self.multithreaded = multithreaded
        self.multiprocess = multiprocess
        self.debug = debug
        self.bind_address = bind_address
        self.umask = umask

    def setup_socket(self):
        old_umask = None
        if type(self.bind_address) is str:
            # Unix socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                os.unlink(self.bind_address)
            except OSError:
                pass
            if self.umask is not None:
                old_umask = os.umask(self.umask)
        else:
            # INET socket
            assert type(self.bind_address) is tuple
            assert len(self.bind_address) == 2
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind(self.bind_address)
        sock.listen(socket.SOMAXCONN)

        if old_umask is not None:
            os.umask(old_umask)

        return sock

    def cleanup_socket(self, sock):
        sock.close()

    def handler(self, request):
        environ = request.environ
        environ.update(self.environ)

        environ['wsgi.version'] = (1,0)
        environ['wsgi.input'] = request.stdin
        environ['wsgi.errors'] = sys.stderr
        environ['wsgi.multithread'] = self.multithreaded
        environ['wsgi.multiprocess'] = self.multiprocess
        environ['wsgi.run_once'] = False

        if environ.get('HTTPS', 'off') in ('on', '1'):
            environ['wsgi.url_scheme'] = 'https'
        else:
            environ['wsgi.url_scheme'] = 'http'

        self.sanitize_env(environ)

        headers_set = []
        headers_sent = []
        result = None

        def write(data):
            assert type(data) is str, 'write() argument must be string'
            assert headers_set, 'write() before start_response()'

            if not headers_sent:
                status, response_headers = headers_sent[:] = headers_set
                found = False
                for header,value in response_headers:
                    if header.lower() == 'content-length':
                        found = True
                        break
                if not found and result is not None:
                    try:
                        if len(result) == 1:
                            response_headers.append(('Content-Length',
                                                    str(len(data))))
                    except:
                        pass
                s = 'Status: %s\r\n' % status
                for header in response_headers:
                    s += '%s: %s\r\n' % header
                s += '\r\n'
                request.stdout.write(s)

            request.stdout.write(data)
            request.stdout.flush()

        def start_response(status, response_headers, exc_info=None):
            if exc_info:
                try:
                    if headers_sent:
                        # Re-raise if too late
                        raise exc_info[0](exc_info[1]).with_traceback(exc_info[2])
                finally:
                    exc_info = None # avoid dangling circular ref
            else:
                assert not headers_set, 'Headers already set!'

            assert type(status) is str, 'Status must be a string'
            assert len(status) >= 4, 'Status must be at least 4 characters'
            assert int(status[:3]), 'Status must begin with 3-digit code'
            assert status[3] == ' ', 'Status must have a space after code'
            assert type(response_headers) is list, 'Headers must be a list'
            if __debug__:
                for name,val in response_headers:
                    assert type(name) is str, 'Header names must be strings'
                    assert type(val) is str, 'Header values must be strings'

            headers_set[:] = [status, response_headers]
            return write

        try:
            result = self.application(environ, start_response)
            try:
                for data in result:
                    if data:
                        write(data)
                if not headers_sent:
                    write('') # in case body was empty
            finally:
                if hasattr(result, 'close'):
                    result.close()
        except socket.error as e:
            if e[0] != errno.EPIPE:
                raise # Don't let EPIPE propagate beyond server

    def sanitize_env(self, environ):
        if 'QUERY_STRING' not in environ:
            environ['QUERY_STRING'] = ''

        script_name = environ.get('WSGI_SCRIPT_NAME')
        if script_name is None:
            script_name = self.script_name
        else:
            warnings.warn(
                'WSGI_SCRIPT_NAME environment variable for scgi servers is deprecated',
                DeprecationWarning)
            if script_name.lower() == 'none':
                script_name = None

        if script_name is None:
            return

        if script_name is NoDefault:
            if 'SCRIPT_NAME' not in environ:
                environ['SCRIPT_INFO'] = ''
            if 'PATH_INFO' not in environ:
                environ['PATH_INFO'] = ''
        else:
            warnings.warn(
                'Configured SCRIPT_NAME is deprecated\n'
                'Do not use WSGI_SCRIPT_NAME or the script_name\n'
                'keyword parameter -- they will be going away',
                DeprecationWarning)

            value = environ['SCRIPT_NAME']
            value += environ.get('PATH_INFO', '')
            if not value.startswith(script_name):
                log.warning('script_name does not match request URI')

            environ['PATH_INFO'] = value[len(script_name):]
            environ['SCRIPT_NAME'] = script_name

    def error(self, request):
        if self.debug:
            import cgitb
            request.stdout.write('Content-Type: text/html\r\n\r\n' + cgitb.html(sys.exc_info()))
        else:
            errorpage = (
                '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">'
                '<html><head>'
                '<title>Unhandled Exception</title>'
                '</head><body>'
                '<h1>Unhandled Exception</h1>'
                '<p>An unhandled exception was thrown by the application.</p>'
                '</body></html>'
            )

            request.stdout.write('Content-Type: text/html\r\n\r\n' + errorpage)


class WSGIServer(BaseSCGIServer):

    def __init__(
            self,
            application,
            **kwargs
    ):
        super(WSGIServer, self).__init__(self, application, **kwargs)

    def run(self):
        log.info('%s starting up', self.__class__.__name__)

        try:
            sock = self.setup_socket()
        except socket.error as e:
            log.error('Failed to bind socket (%s), exiting', e[1])
            return False

        ret = ThreadedServer.run(self, sock)

        while self._keepGoing:
            try:
                r, w, e = select.select([sock], [], [], timeout)
            except select.error as e:
                if e[0] == errno.EINTR:
                    continue
                raise
            if r:
                try:
                    clientSock, addr = sock.accept()
            except socket.error as e:
                if e[0] in (errno.EINTR, errno.EAGAIN):
                    continue
                raise
            setCloseOnExec(clientSock)
            # Hand off to Connection.
            conn = self._jobClass(clientSock, addr, *self._jobArgs)
            if not self._threadPool.addJob(conn, allowQueuing=False):
                # No thread left, immediately close the socket to hopefully
                # indicate to the web server that we're at our limit...
                # and to prevent having too many opened (and useless)
                # files.
                clientSock.close()

        self.cleanup_socket(sock)
        log.info('%s shutting down%s', type(self).__name__, self.hup_received and ' (reload requested)' or '')
        return ret


def factory(global_conf, host=None, port=None, **local):
    from . import paste_factory
    return paste_factory.helper(WSGIServer, global_conf, host, port, **local)


if __name__ == '__main__':
    def test_app(environ, start_response):
        from . import cgi

        start_response('200 OK', [('Content-Type', 'text/html')])

        yield (
            '<html><head><title>Hello World!</title></head>\n'
              '<body>\n'
              '<p>Hello World!</p>\n'
              '<table border="1">'
        )

        names = list(environ.keys())
        names.sort()
        for name in names:
            yield '<tr><td>%s</td><td>%s</td></tr>\n' % (name, cgi.escape(repr(environ[name])))

        form = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ, keep_blank_values=1)
        if form.list:
            yield '<tr><th colspan="2">Form data</th></tr>'

        for field in form.list:
            yield '<tr><td>%s</td><td>%s</td></tr>\n' % (
                field.name, field.value)

        yield (
            '</table>\n'
            '</body></html>\n'
        )

    from wsgiref import validate
    test_app = validate.validator(test_app)
    WSGIServer(test_app).run()
