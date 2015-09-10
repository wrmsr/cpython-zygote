# -*- coding: utf-8 -*-
from __future__ import absolute_import

import ctypes
import resource

from .libc import Malloc

PAGE_SIZE = resource.getpagesize()
PAGE_CAPACITY = PAGE_SIZE - ctypes.sizeof(ctypes.c_void_p) - ctypes.sizeof(ctypes.c_size_t)

class page(ctypes.Structure):
    pass

page_p = ctypes.POINTER(page)

page._fields_ = [
    ('next', page_p),
    ('size', ctypes.c_size_t),
    ('data', ctypes.c_uint8 * PAGE_CAPACITY),
]

def main():
    with Malloc(PAGE_SIZE * 4) as p:
        p = ctypes.cast(p, page_p)
        print(p.contents.next)

if __name__ == '__main__':
    main()
