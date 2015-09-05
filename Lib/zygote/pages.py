# -*- coding: utf-8 -*-
"""https://www.kernel.org/doc/Documentation/filesystems/proc.txt"""
from __future__ import absolute_import

import re
import struct


def parse_size(s):
    us = {'kB': 1024, 'mB': 1024*1024}
    v, u = s.split()
    return int(v) * us[u]

def get_bits(f, t, n):
    return (n & ((1 << (t + 1)) - 1)) >> f

def get_bit(c, n):
    return get_bits(c, c, n)


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
    for k in STATUS_FILE_NUM_KEYS:
        d[k] = parse_size(s[k])
    d['status'] = s
    return d


MAP_LINE_RX = re.compile(
    r'^'
    r'(?P<address>[A-Fa-f0-9]+)-(?P<end_address>[A-Fa-f0-9]+)\s+'
    r'(?P<permissions>\S+)\s+'
    r'(?P<offset>[A-Fa-f0-9]+)\s+'
    r'(?P<device>\S+)\s+'
    r'(?P<inode>\d+)\s+'
    r'(?P<path>.*)'
    r'$')

SMAP_SIZE_LINES = (
    'size',
    'rss',
    'pss',
    'shared_clean',
    'shared_dirty',
    'private_clean',
    'private_dirty',
    'referenced',
    'anonymous',
    'anonhugepages',
    'swap',
    'kernelpagesize',
    'mmupagesize',
    'locked',
)

SMAP_LIST_LINES = (
    'vmflags',
)

def get_maps(pid='self', sharing=False):
    with open('/proc/%s/%s' % (pid, 'smaps' if sharing else 'maps'), 'r') as map_file:
        while True:
            line = map_file.readline()
            if not line:
                break
            m = MAP_LINE_RX.match(line)
            if not m:
                raise ValueError(line)
            address = int(m.group('address'), 16)
            end_address = int(m.group('end_address'), 16)
            d = {
                'address': address,
                'end_address': end_address,
                'size': end_address - address,
                'permissions': [x for x in m.group('permissions') if x != '-'],
                'offset': int(m.group('offset'), 16),
                'device': m.group('device'),
                'inode': int(m.group('inode')),
                'path': m.group('path')
            }
            if sharing:
                s = {}
                for ek in SMAP_SIZE_LINES:
                    line = map_file.readline()
                    k, v = line.split(':')
                    if k.lower() != ek:
                        raise ValueError((k, ek))
                    s[ek] = parse_size(v.strip())
                for ek in SMAP_LIST_LINES:
                    line = map_file.readline()
                    k, v = line.split(':')
                    if k.lower() != ek:
                        raise ValueError((k, ek))
                    s[ek] = [p for p in [j.strip() for j in v.split(' ')] if p]
                d['sharing'] = s
            yield d


PAGEMAP_KEYS = (
    'address',
    'pfn',
    'swap_type',
    'swap_offset',
    'pte_soft_dirty',
    'file_page_or_shared_anon',
    'page_swapped',
    'page_present',
)

def get_range_pagemaps(s, e, pid='self'):
    page_size = 0x1000
    ofs = (s / page_size) * 8
    npages = ((e - s) / page_size)
    sz = npages * 8
    with open('/proc/%s/pagemap' % (pid,), 'rb') as f:
        f.seek(ofs)
        buf = f.read(sz)
    if not buf:
        return
    for i in xrange(npages):
        [n] = struct.unpack('Q', buf[i*8:(i+1)*8])
        yield {
            'address': s + (i * page_size),
            'pfn': get_bits(0, 54, n),
            'swap_type': get_bits(0, 4, n),
            'swap_offset': get_bits(5, 54, n),
            'pte_soft_dirty': bool(get_bit(55, n)),
            'file_page_or_shared_anon': bool(get_bit(61, n)),
            'page_swapped': bool(get_bit(62, n)),
            'page_present': bool(get_bit(63, n)),
        }

def get_pagemaps(pid='self'):
    for m in get_maps(pid):
        for p in get_range_pagemaps(m['address'], m['end_address'], pid):
            yield p


def main():
    import optparse
    import sys

    option_parser = optparse.OptionParser(add_help_option=False, usage='usage: %prog pid')
    option_parser.add_option('-f', '--full', dest='is_full', action='store_true')
    option_parser.add_option('-p', '--pickle', dest='is_pickle', action='store_true')
    option_parser.add_option('-m', '--minimal', dest='is_minimal', action='store_true')
    option_parser.add_option('-i', '--indented', dest='is_indented', action='store_true')

    options, args = option_parser.parse_args()
    if len(args) != 1:
        option_parser.error('invalid arguments')
    pid, = args

    if options.is_minimal:
        def format_pm(pm):
            return tuple(pm[k] for k in PAGEMAP_KEYS)
    else:
        def format_pm(pm):
            return pm

    if options.is_pickle:
        try:
            import cPickle as pickle
        except ImportError:
            import pickle

        lst = []
        for m in get_maps(pid, sharing=True):
            if options.is_full:
                m['mappings'] = list(map(format_pm, get_range_pagemaps(m['address'], m['end_address'], pid)))
            lst.append(m)
        sys.stdout.write(pickle.dumps(lst))

    else:
        import json

        indent = 4 if options.is_indented else None
        for m in get_maps(pid, sharing=True):
            sys.stdout.write(json.dumps({'map': m}, indent=indent))
            sys.stdout.write('\n')
            if options.is_full:
                for pm in get_range_pagemaps(m['address'], m['end_address'], pid):
                    sys.stdout.write(json.dumps({'pagemap': format_pm(pm)}, indent=indent))
                    sys.stdout.write('\n')
        sys.stdout.write('\n')


if __name__ == '__main__':
    main()
