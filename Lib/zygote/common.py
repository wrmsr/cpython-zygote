# -*- coding: utf-8 -*-
from __future__ import absolute_import

import sys
import marshal
import types


def raw_import(name, pyc_path):
    if not pyc_path.endswith('.pyc'):
        raise ValueError(pyc_path)
    with open(pyc_path, 'rb') as f:
        b = f.read()
    c = marshal.loads(b[8:])
    m = types.ModuleType(name)
    sys.modules[name] = m
    m.__dict__['__file__'] = pyc_path
    exec c in m.__dict__
    return m
