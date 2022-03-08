import ctypes
from os.path import join as path_join, abspath, dirname

_DLL_PATH = path_join(dirname(abspath(__file__)), 'libmcleece.so')


class _LibMcleece:
    _dll = None

    def __new__(cls, *args, **kwargs):
        if cls._dll is None:
            cls._dll = ctypes.CDLL(_DLL_PATH)
        return super().__new__(cls, *args, **kwargs)

    def dll(self):
        return self._dll


def libmcleece():
    return _LibMcleece().dll()
