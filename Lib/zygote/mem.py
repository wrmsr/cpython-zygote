# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ctypes import *

pythonapi.PyBuffer_FromMemory.restype = py_object
pythonapi.PyBuffer_FromMemory.argtypes = [c_void_p, c_size_t]

pythonapi.PyBuffer_FromReadWriteMemory.restype = py_object
pythonapi.PyBuffer_FromReadWriteMemory.argtypes = [c_void_p, c_size_t]

pythonapi.PyString_FromString.restype = py_object
pythonapi.PyString_FromString.argtypes = [c_void_p]

def as_buffer(p, sz, rdonly=True):
	if rdonly:
		return pythonapi.PyBuffer_FromMemory(p, sz)
	else:
		return pythonapi.PyBuffer_FromReadWriteMemory(p, sz)
