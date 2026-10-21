# Lance PyInstaller en corrigeant un bug du module dis de Python 3.10.0 (bpo-45757, corrigé en 3.10.1).
# Inutile avec Python >= 3.10.1 : build.ps1 l'utilise automatiquement si besoin.
import dis
import sys
from opcode import HAVE_ARGUMENT, EXTENDED_ARG


def _unpack_opargs(code):
    extended_arg = 0
    for i in range(0, len(code), 2):
        op = code[i]
        if op >= HAVE_ARGUMENT:
            arg = code[i + 1] | extended_arg
            extended_arg = (arg << 8) if op == EXTENDED_ARG else 0
        else:
            arg = None
            extended_arg = 0
        yield (i, op, arg)


dis._unpack_opargs = _unpack_opargs
import PyInstaller.__main__  # noqa: E402

PyInstaller.__main__.run(sys.argv[1:])
