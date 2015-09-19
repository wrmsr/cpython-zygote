# -*- coding: utf-8 -*-
"""
TODO:
- wsgi environ onceover
- mmap for zero-copy responses
"""
from __future__ import absolute_import

import logging

from . import server


log = logging.getLogger(__name__)


class WsgiZygoteServer(ZygoteServer):

    def __init__(
            self,
            path,
            app_factory,
            **kwargs
    ):
        self.nodie = kwargs.pop('nodie', False)
        super(WsgiZygoteServer, self).__init__(path, **kwargs)
        self.app_factory = app_factory
        self.app = None

    def warmup(self):
        if self.app is not None:
            raise TypeError()
        super(WsgiZygoteServer, self).warmup()
        self.app = self.app_factory()

    def serve(self):
        try:
            while True:
                proceed = self.input.read(1)
                if not proceed:
                    break
                if proceed != '\0':
                    raise ValueError(proceed)
                environ = self.readobj()
                if 'wsgi.input' in environ:
                    environ['wsgi.input'] = cStringIO.StringIO(environ['wsgi.input'])
                if 'wsgi.errors' in environ:
                    environ['wsgi.errors'] = log

                def start_response(status, response_headers, exc_info=None):
                    self.writeobjseq(1, status)
                    self.writeobjseq(2, response_headers)
                    self.writeobjseq(3, exc_info)
                try:
                    for buf in self.app(environ, start_response):
                        self.writeobjseq(4, buf)
                except Exception:
                    log.exception('oops')
                self.writeobjseq(5, None)
            log.info('Done')
        except Exception:
            log.exception('oops')
            raise
        finally:
            if not self.nodie:
                os._exit(1)
                raise RuntimeError('unreachable')


class WsgiZygoteClient(ZygoteClient):

    def __call__(self, environ, start_response):
        self.output.write('\0')
        if 'wsgi.input' in environ:
            environ['wsgi.input'] = environ['wsgi.input'].read()
        if 'wsgi.errors' in environ:
            environ['wsgi.errors'] = None
        if 'wsgi.file_wrapper' in environ:
            del environ['wsgi.file_wrapper']
        self.writeobj(environ)
        seq, status = self.readobjseq()
        if seq != 1:
            raise TypeError()
        seq, response_headers = self.readobjseq()
        if seq != 2:
            raise TypeError()
        seq, exc_info = self.readobjseq()
        if seq != 3:
            raise TypeError()
        start_response(status, response_headers, exc_info)
        while True:
            seq, obj = self.readobjseq()
            if seq == 5:
                break
            if seq != 4:
                raise TypeError()
            yield obj


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
