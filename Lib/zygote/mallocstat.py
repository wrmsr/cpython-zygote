# -*- coding: utf-8 -*-
from __future__ import absolute_import

import collections
import ctypes
import hashlib
import sys


class pool_header_ref(ctypes.Union):
    _fields_ = [
        ('_padding', ctypes.c_void_p),
        ('count', ctypes.c_uint),
    ]

class pool_header(ctypes.Structure):
    pass

pool_header_p = ctypes.POINTER(pool_header)
pool_header_pp = ctypes.POINTER(pool_header_p)

# /* Pool for small blocks. */
# struct pool_header {
pool_header._fields_ = [
    # union { block *_padding;
    #	uint count; } ref;              /* number of allocated blocks    */
    ('ref', pool_header_ref),

    # block *freeblock;                 /* pool's free list head         */
    ('freeblock', ctypes.c_void_p),

    # struct pool_header *nextpool;     /* next pool of this size class  */
    ('nextpool', pool_header_p),

    # struct pool_header *prevpool;     /* previous pool       ""        */
    ('prevpool', pool_header_p),

    # uint arenaindex;                  /* index into arenas of base adr */
    ('arenaindex', ctypes.c_uint),

    # uint szidx;                       /* block size class index        */
    ('szidx', ctypes.c_uint),

    # uint nextoffset;                  /* bytes to virgin block         */
    ('nextoffset', ctypes.c_uint),

    # uint maxnextoffset;               /* largest valid nextoffset      */
    ('maxnextoffset', ctypes.c_uint),
]


class arena_object(ctypes.Structure):
    pass

arena_object_p = ctypes.POINTER(arena_object)
arena_object_pp = ctypes.POINTER(arena_object_p)

# /* Record keeping for arenas. */
# struct arena_object {
arena_object._fields_ = [
    # /* The address of the arena, as returned by malloc.  Note that 0
    #  * will never be returned by a successful malloc, and is used
    #  * here to mark an arena_object that doesn't correspond to an
    #  * allocated arena.
    #  */
    # uptr address;
    ('address', ctypes.c_void_p),

    # /* Pool-aligned pointer to the next pool to be carved off. */
    # block* pool_address;
    ('pool_address', pool_header_p),

    # /* The number of available pools in the arena:  free pools + never-
    #  * allocated pools.
    #  */
    # uint nfreepools;
    ('nfreepools', ctypes.c_uint),

    # /* The total number of pools in the arena, whether or not available. */
    # uint ntotalpools;
    ('ntotalpools', ctypes.c_uint),

    # /* Singly-linked list of available pools. */
    # struct pool_header* freepools;
    ('freepools', ctypes.c_void_p),

    # /* Whenever this arena_object is not associated with an allocated
    #  * arena, the nextarena member is used to link all unassociated
    #  * arena_objects in the singly-linked `unused_arena_objects` list.
    #  * The prevarena member is unused in this case.
    #  *
    #  * When this arena_object is associated with an allocated arena
    #  * with at least one available pool, both members are used in the
    #  * doubly-linked `usable_arenas` list, which is maintained in
    #  * increasing order of `nfreepools` values.
    #  *
    #  * Else this arena_object is associated with an allocated arena
    #  * all of whose pools are in use.  `nextarena` and `prevarena`
    #  * are both meaningless in this case.
    #  */
    # struct arena_object* nextarena;
    # struct arena_object* prevarena;
    ('nextarena', arena_object_p),
    ('prevarena', arena_object_p),
]


class alloc_context(ctypes.Structure):
    pass

alloc_context_p = ctypes.POINTER(alloc_context)
alloc_context_pp = ctypes.POINTER(alloc_context_p)

# struct arena_object {
alloc_context._fields_ = [

    # /* Array of objects used to track chunks of memory (arenas). */
    # struct arena_object* arenas;
    ('arenas', arena_object_p),

    # /* Number of slots currently allocated in the `arenas` vector. */
    # uint maxarenas;
    ('maxarenas', ctypes.c_uint),

    # /* The head of the singly-linked, NULL-terminated list of available
    # * arena_objects.
    # */
    # struct arena_object* unused_arena_objects;
    ('unused_arena_objects', arena_object_p),

    # /* The head of the doubly-linked, NULL-terminated at each end, list of
    # * arena_objects associated with arenas that have pools available.
    # */
    # struct arena_object* usable_arenas;
    ('usable_arenas', arena_object_p),

    # /* Number of arenas allocated that haven't been free()'d. */
    # size_t narenas_currently_allocated;
    ('narenas_currently_allocated', ctypes.c_size_t),

    # poolp usedpools[USED_POOL_ARR_SIZE];
    ('usedpools', ctypes.c_void_p),
]


ALIGNMENT = 8
ALIGNMENT_SHIFT = 3
ALIGNMENT_MASK = (ALIGNMENT - 1)

def INDEX2SIZE(x):
    return (x + 1) << ALIGNMENT_SHIFT

SYSTEM_PAGE_SIZE = (4 * 1024)
SYSTEM_PAGE_SIZE_MASK = (SYSTEM_PAGE_SIZE - 1)
ARENA_SIZE = (256 << 10)
POOL_SIZE = SYSTEM_PAGE_SIZE
POOL_SIZE_MASK = SYSTEM_PAGE_SIZE_MASK

def ROUNDUP(x):
    return (x + ALIGNMENT_MASK) & ~ALIGNMENT_MASK

POOL_OVERHEAD = ROUNDUP(ctypes.sizeof(pool_header))

def NUMBLOCKS(x):
    return (POOL_SIZE - POOL_OVERHEAD) // INDEX2SIZE(x)


def debug_malloc_stats():
    numfreepools = 0
    narenas = 0
    arena_alignment = 0

    arenas = parenas.contents
    maxarenas = pmaxarenas.contents.value

    numpools = collections.defaultdict(lambda: 0)
    numblocks = collections.defaultdict(lambda: 0)
    numfreeblocks = collections.defaultdict(lambda: 0)

    for i in xrange(maxarenas):
        arena = parenas.contents[i]

        base = arenas[i].address

        if not base:
            continue

        narenas += 1

        poolsinarena = arenas[i].ntotalpools
        numfreepools += arenas[i].nfreepools

        if base & POOL_SIZE_MASK:
            arena_alignment += POOL_SIZE
            base &= ~POOL_SIZE_MASK
            base += POOL_SIZE

        pool_address = ctypes.addressof(arenas[i].pool_address.contents)

        # visit every pool in the arena
        assert base <= pool_address

        while base < pool_address:
            p = ctypes.cast(base, pool_header_p)

            if p.contents.ref.count > 0:
                sz = p.contents.szidx

                numpools[sz] += 1
                numblocks[sz] += p.contents.ref.count

                freeblocks = NUMBLOCKS(sz) - p.contents.ref.count
                numfreeblocks[sz] += freeblocks

            base += POOL_SIZE

    def fix_dict(d):
        return dict((int(INDEX2SIZE(k)), v) for k, v in d.items())

    def sum_dict(d):
        return sum(k * v for k, v in d.items())

    numpools = fix_dict(numpools)
    numblocks = fix_dict(numblocks)
    numfreeblocks = fix_dict(numfreeblocks)

    return {
        'numfreepools': numfreepools,
        'narenas': narenas,
        'arena_alignment': arena_alignment,
        'numpools': numpools,
        'numblocks': numblocks,
        'totalblocks': sum_dict(numblocks),
        'numfreeblocks': numfreeblocks,
        'totalfreeblocks': sum_dict(numfreeblocks),
    }
