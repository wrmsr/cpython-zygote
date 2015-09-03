# -*- coding: utf-8 -*-
from __future__ import absolute_import

import re

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


* Bits 0-54  page frame number (PFN) if present
* Bits 0-4   swap type if swapped
* Bits 5-54  swap offset if swapped
* Bit  55    pte is soft-dirty (see Documentation/vm/soft-dirty.txt)
* Bits 56-60 zero
* Bit  61    page is file-page or shared-anon
* Bit  62    page swapped
* Bit  63    page present
