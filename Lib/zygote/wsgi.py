# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from . import server


log = logging.getLogger(__name__)


class WsgiZygoteServer(ZygoteServer):

    def __init__(self, path, app, **kwargs):
        super(WsgiZygoteServer, self).__init__(path, **kwargs)
        self.app = app

    def handshake(self):
        super(WsgiZygoteServer, self).handshake()
        self.setup_deathpact()

    def work(self):
        while True:
            environ = self.readobj()
            if 'wsgi.input' in environ:
                environ['wsgi.input'] = cStringIO.StringIO(environ['wsgi.input'])
            if 'wsgi.errors' in environ:
                environ['wsgi.errors'] = log
            def start_response(status, response_headers, exc_info=None):
                self.writeobj(status)
                self.writeobj(response_headers)
                self.writeobj(exc_info)
            try:
                for buf in self.app(environ, start_response):
                    self.write(buf)
            except Exception as e:
                log.error(repr(e))
            self.write('')


class WsgiZygoteClient(ZygoteClient):

    def handshake(self):
        super(WsgiZygoteClient, self).handshake()
        self.setup_deathpact()

    def __call__(self, environ, start_response):
        if 'wsgi.input' in environ:
            environ['wsgi.input'] = environ['wsgi.input'].read()
        if 'wsgi.errors' in environ:
            environ['wsgi.errors'] = None
        if 'wsgi.file_wrapper' in environ:
            del environ['wsgi.file_wrapper']
        self.writeobj(environ)
        status, response_headers, exc_info = self.readobj(), self.readobj(), self.readobj()
        start_response(status, response_headers, exc_info)
        while True:
            buf = self.read()
            if not buf:
                break
            yield buf


def main():
    import optparse

    option_parser = optparse.OptionParser(add_help_option=False, usage='usage: %prog path')
    option_parser.add_option('-s', '--server', dest='is_server', action='store_true')
    option_parser.add_option('-v', '--verbose', dest='is_verbose', action='store_true')

    options, args = option_parser.parse_args()
    if len(args) != 1:
        option_parser.error('invalid arguments')
    path, = args


if __name__ == '__main__':
    main()
