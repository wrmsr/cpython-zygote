# -*- coding: utf-8 -*-
import contextlib
import optparse
import os
import signal
import socket
import struct
import sys
import traceback

socket.SCM_RIGHTS = 1
socket.SO_PASSCRED = 16
socket.SO_PEERCRED = 17

try:
    # https://pypi.python.org/pypi/python-passfd/0.1
    import passfd

    sendfd = passfd.sendfd
    recvfd = passfd.recvfd

except Exception:
    # https://code.google.com/p/python-passfd/source/browse/src/passfd.c
    import ctypes

    ctypes.c_ssize_t = ctypes.c_size_t

    libc = ctypes.CDLL('libc.so.6')

    class iovec(ctypes.Structure): pass
    iovec._fields_ = [
        ('iov_base', ctypes.c_void_p), # Pointer to data.
        ('iov_len', ctypes.c_size_t), # Length of data.
    ]

    class msghdr(ctypes.Structure): pass
    msghdr._fields_ = [
        ('msg_name', ctypes.c_void_p),			# Address to send to/receive from.
        ('msg_namelen', ctypes.c_uint),			# Length of address data.
        ('msg_iov', ctypes.POINTER(iovec)),		# Vector of data to send/receive into.
        ('msg_iovlen', ctypes.c_size_t),		# Number of elements in the vector.
        ('msg_control', ctypes.c_void_p),		# Ancillary data (eg BSD filedesc passing).
        ('msg_controllen', ctypes.c_size_t),	# Ancillary data buffer length. !! The type should be
                                                # socklen_t but the definition of the kernel is
                                                # incompatible with this
        ('msg_flags', ctypes.c_int),			# Flags on received message.
    ]

    class cmsghdr(ctypes.Structure): pass
    cmsghdr._fields_ = [
        ('cmsg_len', ctypes.c_size_t),	# Length of data in cmsg_data plus length
                                        # of cmsghdr structure. !! The type should be socklen_t but the
                                        # definition of the kernel is incompatible with this.
        ('cmsg_level', ctypes.c_int),	# Originating protocol.
        ('cmsg_type', ctypes.c_int),	# Protocol specific type.
    ]

    # ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
    libc.sendmsg.restype = ctypes.c_ssize_t
    libc.sendmsg.argtypes = [ctypes.c_int, ctypes.POINTER(msghdr), ctypes.c_int]

    # ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
    libc.sendmsg.restype = ctypes.c_ssize_t
    libc.sendmsg.argtypes = [ctypes.c_int, ctypes.POINTER(msghdr), ctypes.c_int]

    def CMSG_ALIGN(sz):
        i = ctypes.sizeof(ctypes.c_size_t)
        return ((sz + i - 1) // i) * i

    def CMSG_SPACE(sz):
        return CMSG_ALIGN(sz) + CMSG_ALIGN(ctypes.sizeof(cmsghdr))

    def CMSG_LEN(sz):
        return CMSG_ALIGN(ctypes.sizeof(cmsghdr)) + sz

    def sendfd(sock, fd, data='.'):
        if not data:
            raise ValueError(data)

        iov = iovec()
        iov.iov_base = ctypes.cast(ctypes.c_char_p(data), ctypes.c_void_p)
        iov.iov_len  = len(data)

        cmsg_size = CMSG_SPACE(ctypes.sizeof(ctypes.c_int))
        msg_control = (ctypes.c_char * cmsg_size)()

        msgh = msghdr()
        msgh.msg_name       = None
        msgh.msg_namelen    = 0
        msgh.msg_iov        = ctypes.cast(ctypes.addressof(iov), ctypes.POINTER(iovec))
        msgh.msg_iovlen     = 1
        msgh.msg_control    = ctypes.cast(ctypes.addressof(msg_control), ctypes.c_void_p)
        msgh.msg_controllen = cmsg_size
        msgh.msg_flags      = 0

        h = ctypes.cast(ctypes.addressof(msg_control), ctypes.POINTER(cmsghdr))
        h.contents.cmsg_len   = CMSG_LEN(ctypes.sizeof(ctypes.c_int))
        h.contents.cmsg_level = socket.SOL_SOCKET
        h.contents.cmsg_type  = socket.SCM_RIGHTS

        p_fd = ctypes.cast(
            ctypes.addressof(msg_control) + ctypes.sizeof(cmsghdr),
            ctypes.POINTER(ctypes.c_int))
        p_fd.contents = ctypes.c_int(fd)

        return libc.sendmsg(sock, msgh, 0)

    def recvfd(sock, buf_len=4096):
        if buf_len < 1:
            raise ValueError(buf_len)

        cmsg_size = CMSG_SPACE(ctypes.sizeof(ctypes.c_int))
        cmsg_buf = (ctypes.c_char * cmsg_size)()
        data_buf = (ctypes.c_char * buf_len)()

        iov = iovec()
        iov.iov_base = ctypes.cast(ctypes.addressof(data_buf), ctypes.c_void_p)
        iov.iov_len  = buf_len

        msgh = msghdr()
        msgh.msg_name       = None
        msgh.msg_namelen    = 0
        msgh.msg_iov        = ctypes.cast(ctypes.addressof(iov), ctypes.POINTER(iovec))
        msgh.msg_iovlen     = 1
        msgh.msg_control    = ctypes.cast(ctypes.addressof(cmsg_buf), ctypes.c_void_p)
        msgh.msg_controllen = cmsg_size
        msgh.msg_flags      = 0

        recv_len = libc.recvmsg(sock, ctypes.cast(ctypes.addressof(msgh), ctypes.POINTER(msghdr)), 0)
        if recv_len < 0:
            return recv_len, None

        h = ctypes.cast(ctypes.addressof(cmsg_buf), ctypes.POINTER(cmsghdr))
        if (h.contents.cmsg_len != CMSG_LEN(ctypes.sizeof(ctypes.c_int))) or \
            (h.contents.cmsg_level != socket.SOL_SOCKET) or \
            (h.contents.cmsg_type != socket.SCM_RIGHTS):
            return -2, None

        p_fd = ctypes.cast(
            ctypes.addressof(cmsg_buf) + ctypes.sizeof(cmsghdr),
            ctypes.POINTER(ctypes.c_int))
        fd = p_fd.contents.value
        if fd < 0:
            return -3, None

        return fd, data_buf[:recv_len]
