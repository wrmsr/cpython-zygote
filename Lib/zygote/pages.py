# -*- coding: utf-8 -*-
from __future__ import absolute_import

import re
import struct


MAP_FILE_RX = re.compile(
    r'^'
    r'(?P<address>[A-Fa-f0-9]+)-(?P<end_address>[A-Fa-f0-9]+)\s+'
    r'(?P<permissions>\S+)\s+'
    r'(?P<offset>[A-Fa-f0-9]+)\s+'
    r'(?P<device>\S+)\s+'
    r'(?P<inode>\d+)\s+'
    r'(?P<path>.*)'
    r'$')

def get_maps(pid='self'):
    with open('/proc/%s/maps' % (pid,), 'r') as map_file:
        for line in map_file:
            m = MAP_FILE_RX.match(line)
            if not m:
                raise ValueError(line)
            address = int(m.group('address'), 16)
            end_address = int(m.group('end_address'), 16)
            yield {
                'address': address,
                'end_address': end_address,
                'size': end_address - address,
                'permissions': m.group('permissions'),
                'offset': int(m.group('offset'), 16),
                'device': m.group('device'),
                'inode': int(m.group('inode')),
                'path': m.group('path')
            }


STATM_FILE_KEYS = (
    'size',
    'resident',
    'share',
    'text',
    'lib',
    'data',
    'dt',
)

STATUS_FILE_NUM_KEYS = (
    'vmdata',
    'vmexe',
    'vmhwm',
    'vmlck',
    'vmlib',
    'vmpeak',
    'vmpte',
    'vmrss',
    'vmsize',
    'vmstk',
)

def get_status(pid='self'):
    d = {}
    with open('/proc/%s/stat' % (pid,), 'r') as f:
        d['stat'] = f.readline()
    with open('/proc/%s/statm' % (pid,), 'r') as f:
        d['statm'] = dict(zip(STATM_FILE_KEYS, map(int, f.readline().split())))
    with open('/proc/%s/status' % (pid,), 'r') as f:
        s = dict((k.lower(), v.strip()) for k, v in (l.strip().split(':') for l in f.readlines()))
    us = {'kB': 1024, 'mB': 1024*1024}
    for k in STATUS_FILE_NUM_KEYS:
        v, u = s[k].split()
        s[k] = int(v) * us[u]
    d['status'] = s
    return d


def get_bits(f, t, n):
    return (n&((1<<(t+1))-1))>>f

def get_bit(c, n):
    return get_bits(c, c, n)


def get_range_pagemap(s, e, pid='self'):
    import pdb; pdb.set_trace()
    page_size = 0x1000
    ofs = (s / page_size) * 8
    sz = ((e - s) / page_size) * 8
    with open('/proc/%s/pagemap' % (pid,), 'rb') as f:
        f.seek(ofs)
        buf = f.read(sz)
    for i, a in enumerate(xrange(s, e, page_size)):
        [n] = struct.unpack('Q', buf[i*8:(i+1)*8])
        yield {
            'address': a,
            'pfn': get_bits(0, 54, n),
            'swap_type': get_bits(0, 4, n),
            'swap_offset': get_bits(5, 54, n),
            'pte_soft_dirty': get_bit(55, n),
            'file_page_or_shared_anon': get_bit(61, n),
            'page_swapped': get_bit(62, n),
            'page_present': get_bit(63, n),
        }

def get_pagemap(pid='self'):
    for m in get_maps(pid):
        for p in get_range_pagemap(m['address'], m['end_address'], pid):
            yield p
