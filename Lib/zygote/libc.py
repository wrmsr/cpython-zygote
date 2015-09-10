# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ctypes import *

libc = CDLL('libc.so.6')

libc.malloc.restype = c_void_p
libc.malloc.argtypes = [c_size_t]

libc.free.restype = c_void_p
libc.free.argtypes = [c_void_p]

# void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
libc.mmap.restype = c_void_p
libc.mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_size_t]

# int munmap(void *addr, size_t length);
libc.munmap.restype = c_int
libc.munmap.argtypes = [c_void_p, c_size_t]

# int mprotect(const void *addr, size_t len, int prot);
libc.mprotect.restype = c_int
libc.mprotect.argtypes = [c_void_p, c_size_t, c_int]

libc.PROT_READ		= 0x1			# Page can be read.
libc.PROT_WRITE		= 0x2			# Page can be written.
libc.PROT_EXEC		= 0x4			# Page can be executed.
libc.PROT_NONE		= 0x0			# Page can not be accessed.
libc.PROT_GROWSDOWN	= 0x01000000	# Extend change to start of growsdown vma (mprotect only).
libc.PROT_GROWSUP	= 0x02000000	# Extend change to start of growsup vma (mprotect only).

libc.MAP_SHARED		= 0x01			# Share changes.
libc.MAP_PRIVATE		= 0x02			# Changes are private.
libc.MAP_GROWSDOWN	= 0x00100		# Stack-like segment.
libc.MAP_DENYWRITE	= 0x00800		# ETXTBSY
libc.MAP_EXECUTABLE	= 0x01000		# Mark it as an executable.
libc.MAP_LOCKED		= 0x02000		# Lock the mapping.
libc.MAP_NORESERVE	= 0x04000		# Don't check for reservations.
libc.MAP_POPULATE	= 0x08000		# Populate (prefault) pagetables.
libc.MAP_NONBLOCK	= 0x10000		# Do not block on IO.
libc.MAP_STACK		= 0x20000		# Allocation is for a stack.
libc.MAP_HUGETLB		= 0x40000		# create a huge page mapping

# int msync(void *addr, size_t length, int flags);
libc.msync.restype = c_int
libc.msync.argtypes = [c_void_p, c_size_t, c_int]

libc.MS_ASYNC		= 1		# Sync memory asynchronously.
libc.MS_SYNC			= 4		# Synchronous memory sync.
libc.MS_INVALIDATE	= 2		# Invalidate the caches.

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

libc.MCL_CURRENT	= 1		# Lock all currently mapped pages.
libc.MCL_FUTURE	= 2		# Lock all additions to address space.

# void *mremap(void *old_address, size_t old_size, size_t new_size, int flags);
libc.mremap.restype = c_void_p
libc.mremap.argtypes = [c_void_p, c_size_t, c_size_t, c_int]

libc.MREMAP_MAYMOVE	= 1
libc.MREMAP_FIXED	= 2

# ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
libc.splice.restype = c_size_t
libc.splice.argtypes = [c_int, POINTER(c_size_t), c_int, POINTER(c_size_t), c_size_t, c_uint]

libc.SPLICE_F_MOVE		= 1		# Move pages instead of copying.
libc.SPLICE_F_NONBLOCK	= 2		# Don't block on the pipe splicing (but we may still block on the fd we splice from/to).
libc.SPLICE_F_MORE		= 4		# Expect more data.
libc.SPLICE_F_GIFT		= 8		# Pages passed in are a gift.

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
        return self.base

    def __exit__(self, et, e, tb):
        if self.base != 0:
            libc.free(self.base)
        self.base = 0

    def __int__(self):
        return int(self.base)

    def __long__(self):
        return long(self.base)