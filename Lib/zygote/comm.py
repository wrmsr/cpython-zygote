# -*- coding: utf-8 -*-
from __future__ import absolute_import

import ctypes

libc = ctypes.CDLL('libc.so.6')

class page(ctypes.Structure):
    pass

page_p = ctypes.POINTER(page)

page_p._fields_ = [
    ('next', page_p),  # Pointer to data.
    ('size', ctypes.c_size_t),   # Length of data.
    ('data', ctypes.c_uint8),   # Length of data.
]

def main():
    pass

if __name__ == '__main__':
    main()
