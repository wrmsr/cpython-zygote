# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from . import server


log = logging.getLogger(__name__)


class WsgiZygoteServer(server.ZygoteServer):

    def __init__(self, path, app, **kwargs):
        super(WsgiZygoteServer, self).__init__(path, **kwargs)

    def work(self):
        while True:
            environ = self.writeobj()
            def start_response(status, response_headers, exc_info=None):
                self.writeobj(status)
                self.writeobj(response_headers)
                self.writeobj(exc_info)
            for buf in self.application(environ, start_response):
                self.write(buf)


class WsgiZygoteClient(server.ZygoteClient):

    def __call__(self, environ, start_response):
        self.writeobj(environ)
        status, response_headers, exc_info = self.readobj(), self.reodobj(), self.readobj()
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
