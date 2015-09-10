#include "Python.h"

#include "liblfds611.h"

PyDoc_STRVAR(lfds_hi_doc, "lfds_hi\n");

static PyObject *
lfds_hi(PyObject *self, PyObject *args, PyObject *kw)
{
    lfds611_queue_new(NULL, 1);
    Py_RETURN_NONE;
}

static PyMethodDef lfds_methods[] = {
    {"lfds_hi", (PyCFunction)lfds_hi,
        METH_VARARGS|METH_KEYWORDS, lfds_hi_doc},
    {NULL, NULL} /* sentinel */
};

PyDoc_STRVAR(module_doc, "_lfds\n");

PyMODINIT_FUNC
init_lfds(void)
{
    Py_InitModule3("_lfds", lfds_methods, module_doc);
}
