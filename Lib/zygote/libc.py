# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ctypes import *

libc = CDLL('libc.so.6')

# void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
libc.mmap.restype = c_void_p
libc.mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_size_t]

# int munmap(void *addr, size_t length);
libc.munmap.restype = c_int
libc.munmap.argtypes = [c_void_p, c_size_t]

# int mprotect(const void *addr, size_t len, int prot);
libc.mprotect.restype = c_int
libc.mprotect.argtypes = [c_void_p, c_size_t, c_int]

PROT_READ		= 0x1			# Page can be read.
PROT_WRITE		= 0x2			# Page can be written.
PROT_EXEC		= 0x4			# Page can be executed.
PROT_NONE		= 0x0			# Page can not be accessed.
PROT_GROWSDOWN	= 0x01000000	# Extend change to start of growsdown vma (mprotect only).
PROT_GROWSUP	= 0x02000000	# Extend change to start of growsup vma (mprotect only).

MAP_SHARED		= 0x01			# Share changes.
MAP_PRIVATE		= 0x02			# Changes are private.
MAP_GROWSDOWN	= 0x00100		# Stack-like segment.
MAP_DENYWRITE	= 0x00800		# ETXTBSY
MAP_EXECUTABLE	= 0x01000		# Mark it as an executable.
MAP_LOCKED		= 0x02000		# Lock the mapping.
MAP_NORESERVE	= 0x04000		# Don't check for reservations.
MAP_POPULATE	= 0x08000		# Populate (prefault) pagetables.
MAP_NONBLOCK	= 0x10000		# Do not block on IO.
MAP_STACK		= 0x20000		# Allocation is for a stack.
MAP_HUGETLB		= 0x40000		# create a huge page mapping

# int msync(void *addr, size_t length, int flags);
libc.msync.restype = c_int
libc.msync.argtypes = [c_void_p, c_size_t, c_int]

MS_ASYNC		= 1		# Sync memory asynchronously.
MS_SYNC			= 4		# Synchronous memory sync.
MS_INVALIDATE	= 2		# Invalidate the caches.

# int mlock(const void *addr, size_t len);
libc.mlock.restype = c_int
libc.mlock.argtypes = [c_void_p, c_size_t]

# int munlock(const void *addr, size_t len);
libc.munlock.restype = c_int
libc.munlock.argtypes = [c_void_p, c_size_t]

# int mlockall(int flags);
libc.mlockall.restype = c_int
libc.mlockall.argtypes = [c_int]

# int munlockall(void);
libc.munlockall.restype = c_int
libc.munlockall.argtypes = []

MCL_CURRENT	= 1		# Lock all currently mapped pages.
MCL_FUTURE	= 2		# Lock all additions to address space.

# void *mremap(void *old_address, size_t old_size, size_t new_size, int flags);
libc.mremap.restype = c_void_p
libc.mremap.argtypes = [c_void_p, c_size_t, c_size_t, c_int]

MREMAP_MAYMOVE	= 1
MREMAP_FIXED	= 2

# ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
libc.splice.restype = c_size_t
libc.splice.argtypes = [c_int, POINTER(c_size_t), c_int, POINTER(c_size_t), c_size_t, c_uint]

SPLICE_F_MOVE		= 1		# Move pages instead of copying.
SPLICE_F_NONBLOCK	= 2		# Don't block on the pipe splicing (but we may still block on the fd we splice from/to).
SPLICE_F_MORE		= 4		# Expect more data.
SPLICE_F_GIFT		= 8		# Pages passed in are a gift.

# int raise(int sig);
libc._raise = libc['raise']
libc._raise.restype = c_int
libc._raise.argtypes = [c_int]


def sigtrap():
    libc._raise(signal.SIGTRAP)

class Malloc(object):

    def __init__(self, sz):
        self.sz = sz
        self.base = 0

    def __enter__(self):
        self.base = libc.malloc(self.sz)

    def __exit__(self, et, e, tb):
        libc.free(self.base)
        self.base = 0

    def __int__(self):
        return int(self.base)

    def __long__(self):
        return long(self.base)
