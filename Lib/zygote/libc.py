# -*- coding: utf-8 -*-
from __future__ import absolute_import

import sys

from ctypes import *

LINUX_PLATFORMS = ('linux', 'linux2')
DARWIN_PLATFORMS = ('darwin',)

LINUX = False
DARWIN = False

if sys.platform in LINUX_PLATFORMS:
    libc = CDLL('libc.so.6')
    LINUX = True
elif sys.platform in DARWIN_PLATFORMS:
    libc = CDLL('/usr/lib/libc.dylib')
    DARWIN = True
else:
    raise EnvironmentError('Unsupported platform')

# void *dlopen(const char *filename, int flag);
# char *dlerror(void);
# void *dlsym(void *handle, const char *symbol);
# int dlclose(void *handle);

libc.malloc.restype = c_void_p
libc.malloc.argtypes = [c_size_t]

libc.free.restype = None
libc.free.argtypes = [c_void_p]

# void *memcpy(void *dest, const void *src, size_t n);
libc.memcpy.restype = c_void_p
libc.memcpy.argtypes = [c_void_p, c_void_p, c_size_t]

# void *memset(void *s, int c, size_t n);
libc.memset.restype = c_void_p
libc.memset.argtypes = [c_void_p, c_int, c_size_t]

# int memcmp(const void *s1, const void *s2, size_t n);
libc.memcmp.restype = c_int
libc.memcmp.argtypes = [c_void_p, c_void_p, c_size_t]

# void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
libc.mmap.restype = None
libc.mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_size_t]

# int munmap(void *addr, size_t length);
libc.munmap.restype = c_int
libc.munmap.argtypes = [c_void_p, c_size_t]

# int mprotect(const void *addr, size_t len, int prot);
libc.mprotect.restype = c_int
libc.mprotect.argtypes = [c_void_p, c_size_t, c_int]

libc.PROT_READ        = 0x1           # Page can be read.
libc.PROT_WRITE       = 0x2           # Page can be written.
libc.PROT_EXEC        = 0x4           # Page can be executed.
libc.PROT_NONE        = 0x0           # Page can not be accessed.
libc.PROT_GROWSDOWN   = 0x01000000    # Extend change to start of growsdown vma (mprotect only).
libc.PROT_GROWSUP     = 0x02000000    # Extend change to start of growsup vma (mprotect only).

libc.MAP_SHARED       = 0x01           # Share changes.
libc.MAP_PRIVATE      = 0x02           # Changes are private.
libc.MAP_GROWSDOWN    = 0x00100        # Stack-like segment.
libc.MAP_DENYWRITE    = 0x00800        # ETXTBSY
libc.MAP_EXECUTABLE   = 0x01000        # Mark it as an executable.
libc.MAP_LOCKED       = 0x02000        # Lock the mapping.
libc.MAP_NORESERVE    = 0x04000        # Don't check for reservations.
libc.MAP_POPULATE     = 0x08000        # Populate (prefault) pagetables.
libc.MAP_NONBLOCK     = 0x10000        # Do not block on IO.
libc.MAP_STACK        = 0x20000        # Allocation is for a stack.
libc.MAP_HUGETLB      = 0x40000        # create a huge page mapping

# int msync(void *addr, size_t length, int flags);
libc.msync.restype = c_int
libc.msync.argtypes = [c_void_p, c_size_t, c_int]

libc.MS_ASYNC         = 1        # Sync memory asynchronously.
libc.MS_SYNC          = 4        # Synchronous memory sync.
libc.MS_INVALIDATE    = 2        # Invalidate the caches.

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

libc.MCL_CURRENT    = 1        # Lock all currently mapped pages.
libc.MCL_FUTURE     = 2        # Lock all additions to address space.

# void *mremap(void *old_address, size_t old_size, size_t new_size, int flags);
libc.mremap.restype = c_void_p
libc.mremap.argtypes = [c_void_p, c_size_t, c_size_t, c_int]

libc.MREMAP_MAYMOVE    = 1
libc.MREMAP_FIXED    = 2

# ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
libc.splice.restype = c_size_t
libc.splice.argtypes = [c_int, POINTER(c_size_t), c_int, POINTER(c_size_t), c_size_t, c_uint]

libc.SPLICE_F_MOVE        = 1        # Move pages instead of copying.
libc.SPLICE_F_NONBLOCK    = 2        # Don't block on the pipe splicing (but we may still block on the fd we splice from/to).
libc.SPLICE_F_MORE        = 4        # Expect more data.
libc.SPLICE_F_GIFT        = 8        # Pages passed in are a gift.

# int raise(int sig);
libc._raise = libc['raise']
libc._raise.restype = c_int
libc._raise.argtypes = [c_int]

if LINUX:
    libc.EFD_SEMAPHORE = 1,
    libc.EFD_SEMAPHORE = libc.EFD_SEMAPHORE
    libc.EFD_CLOEXEC = 02000000,
    libc.EFD_CLOEXEC = libc.EFD_CLOEXEC
    libc.EFD_NONBLOCK = 04000
    libc.EFD_NONBLOCK = libc.EFD_NONBLOCK

    # extern int eventfd (int __count, int __flags) __THROW;
    libc.eventfd.restype = c_int
    libc.eventfd.argtypes = [c_int, c_int]

    # extern int eventfd_read (int __fd, eventfd_t *__value);
    libc.eventfd_read.restype = c_int
    libc.eventfd_read.argtypes = [c_int, POINTER(c_uint64)]

    # extern int eventfd_write (int __fd, eventfd_t __value);
    libc.eventfd_write.restype = c_int
    libc.eventfd_write.argtypes = [c_int, c_uint64]

    # int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]

    # Values to pass as first argument to prctl()
    libc.PR_SET_PDEATHSIG = 1  # Second arg is a signal
    libc.PR_GET_PDEATHSIG = 2  # Second arg is a ptr to return the signal

    # Get/set current->mm->dumpable
    libc.PR_GET_DUMPABLE = 3
    libc.PR_SET_DUMPABLE = 4

    # Get/set unaligned access control bits (if meaningful)
    libc.PR_GET_UNALIGN = 5
    libc.PR_SET_UNALIGN = 6
    libc.PR_UNALIGN_NOPRINT = 1  # silently fix up unaligned user accesses
    libc.PR_UNALIGN_SIGBUS = 2  # generate SIGBUS on unaligned user access

    # Get/set whether or not to drop capabilities on setuid() away from
    # uid 0 (as per security/commoncap.c)
    libc.PR_GET_KEEPCAPS = 7
    libc.PR_SET_KEEPCAPS = 8

    # Get/set floating-point emulation control bits (if meaningful)
    libc.PR_GET_FPEMU = 9
    libc.PR_SET_FPEMU = 10
    libc.PR_FPEMU_NOPRINT = 1  # silently emulate fp operations accesses
    libc.PR_FPEMU_SIGFPE = 2  # don't emulate fp operations, send SIGFPE instead

    # Get/set floating-point exception mode (if meaningful)
    libc.PR_GET_FPEXC = 11
    libc.PR_SET_FPEXC = 12
    libc.PR_FP_EXC_SW_ENABLE = 0x80  # Use FPEXC for FP exception enables
    libc.PR_FP_EXC_DIV = 0x010000  # floating point divide by zero
    libc.PR_FP_EXC_OVF = 0x020000  # floating point overflow
    libc.PR_FP_EXC_UND = 0x040000  # floating point underflow
    libc.PR_FP_EXC_RES = 0x080000  # floating point inexact result
    libc.PR_FP_EXC_INV = 0x100000  # floating point invalid operation
    libc.PR_FP_EXC_DISABLED = 0  # FP exceptions disabled
    libc.PR_FP_EXC_NONRECOV = 1  # async non-recoverable exc. mode
    libc.PR_FP_EXC_ASYNC = 2  # async recoverable exception mode
    libc.PR_FP_EXC_PRECISE = 3  # precise exception mode

    # Get/set whether we use statistical process timing or accurate timestamp
    # process timing
    libc.PR_SET_NAME = 15  # Set process name
    libc.PR_GET_NAME = 16  # Get process name

    # Get/set process endian
    libc.PR_GET_ENDIAN = 19
    libc.PR_SET_ENDIAN = 20
    libc.PR_ENDIAN_BIG = 0
    libc.PR_ENDIAN_LITTLE = 1  # True little endian mode
    libc.PR_ENDIAN_PPC_LITTLE = 2  # "PowerPC" pseudo little endian

    # Get/set process seccomp mode
    libc.PR_GET_SECCOMP = 21
    libc.PR_SET_SECCOMP = 22

    # Get/set the capability bounding set (as per security/commoncap.c)
    libc.PR_CAPBSET_READ = 23
    libc.PR_CAPBSET_DROP = 24

    # Get/set the process' ability to use the timestamp counter instruction
    libc.PR_GET_TSC = 25
    libc.PR_SET_TSC = 26
    libc.PR_TSC_ENABLE = 1  # allow the use of the timestamp counter
    libc.PR_TSC_SIGSEGV = 2  # throw a SIGSEGV instead of reading the TSC

    # Get/set securebits (as per security/commoncap.c)
    libc.PR_GET_SECUREBITS = 27
    libc.PR_SET_SECUREBITS = 28

    # Get/set the timerslack as used by poll/select/nanosleep
    # A value of 0 means "use default"
    libc.PR_SET_TIMERSLACK = 29
    libc.PR_GET_TIMERSLACK = 30

    libc.PR_TASK_PERF_EVENTS_DISABLE = 31
    libc.PR_TASK_PERF_EVENTS_ENABLE = 32

    # Set early/late kill mode for hwpoison memory corruption.
    # This influences when the process gets killed on a memory corruption.
    libc.PR_MCE_KILL = 33
    libc.PR_MCE_KILL_CLEAR = 0
    libc.PR_MCE_KILL_SET = 1

    libc.PR_MCE_KILL_LATE = 0
    libc.PR_MCE_KILL_EARLY = 1
    libc.PR_MCE_KILL_DEFAULT = 2

    libc.PR_MCE_KILL_GET = 34


def sigtrap():
    libc._raise(signal.SIGTRAP)


class Malloc(object):

    def __init__(self, arg):
        super(Malloc, self).__init__()
        self.arg = arg
        self.base = 0

    def __enter__(self):
        if isinstance(self.arg, numbers.Integral):
            self.base = libc.malloc(self.arg)
            return self.base
        else:
            ty = ctypes.POINTER(self.arg)
            self.base = libc.malloc(ctypes.sizeof(self.arg))
            return ctypes.cast(self.base, ty)

    def __exit__(self, et, e, tb):
        if self.base != 0:
            libc.free(self.base)
        self.base = 0

    def __int__(self):
        return int(self.base)

    def __long__(self):
        return long(self.base)


dl = ctypes.CDLL('libdl.so.2')

dl.dlopen.restype = ctypes.c_void_p
dl.dlopen.argtypes = [ctypes.c_char_p, ctypes.c_int]

dl.dlsym.restype = ctypes.c_uint64
dl.dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
