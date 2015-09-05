#include "Python.h"

void *_PyMem_PinnedBase = (void *) 0;
void *_PyMem_PinnedEnd = (void *) 0;

PyMODINIT_FUNC
init_gc_pin_shim(void)
{
    (void) Py_InitModule("_gc_pin_shim", NULL);
}
