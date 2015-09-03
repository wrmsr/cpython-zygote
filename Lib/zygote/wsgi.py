# -*- coding: utf-8 -*-
from __future__ import absolute_import

import abc
import logging

from . import server


log = logging.getLogger(__name__)


class WsgiZygoteServer(server.ZygoteServer):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __call__(self, environ, start_response):
        raise NotImplementedError()


class WsgiZygoteClient(server.ZygoteClient):

    def __call__(self, environ, start_response):
        raise NotImplementedError()
