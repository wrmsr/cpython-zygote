# -*- coding: utf-8 -*-
from __future__ import absolute_import

import ctypes
import resource

from .libc import Malloc

class page(ctypes.Structure):
    pass

page_p = ctypes.POINTER(page)

page._fields_ = [
    ('next', page_p),  # Pointer to data.
    ('size', ctypes.c_size_t),   # Length of data.
    ('data', ctypes.c_uint8),   # Length of data.
]

def main():
    page_size = resource.getpagesize()
    with Malloc(page_size * 4) as p:
        p = ctypes.cast(p, page_p)
        print(p.contents.next)

if __name__ == '__main__':
    main()
