import ctypes
import sys

import idaapi
import idc

from . import const
from idaapi import til_t
import HexRaysPyTools.forms as forms


def _enable_library_ordinals(library_num):
    idaname = "ida64" if const.EA64 else "ida"
    if sys.platform == "win32":
        dll = ctypes.windll[idaname + ".dll"]
    elif sys.platform == "linux2":
        dll = ctypes.cdll["lib" + idaname + ".so"]
    elif sys.platform == "darwin":
        dll = ctypes.cdll["lib" + idaname + ".dylib"]
    else:
        print("[ERROR] Failed to enable ordinals")
        return

    print("HexRaysPyTools DLL: {}".format(dll))

    dll.get_idati.restype = ctypes.POINTER(til_t)
    idati = dll.get_idati()
    dll.enable_numbered_types(idati.contents.base[library_num], True)


def choose_til():
    # type: () -> (idaapi.til_t, int, bool)
    """ Creates a list of loaded libraries, asks user to take one of them and returns it with
    information about max ordinal and whether it's local or imported library """
    idati = idaapi.get_idati()
    list_type_library = [(idati, idati.name, idati.desc)]
    for idx in range(idati.nbases):
        type_library = idati.base(idx)          # type: idaapi.til_t
        list_type_library.append((type_library, type_library.name, type_library.desc))

    library_chooser = forms.MyChoose(
        list([[x[1], x[2]] for x in list_type_library]),
        "Select Library",
        [["Library", 10 | idaapi.Choose.CHCOL_PLAIN], ["Description", 30 | idaapi.Choose.CHCOL_PLAIN]],
        69
    )
    library_num = library_chooser.Show(True)
    if library_num != -1:
        selected_library = list_type_library[library_num][0]    # type: idaapi.til_t
        max_ordinal = idaapi.get_ordinal_count(selected_library)
        if max_ordinal == idaapi.BADORD:
            _enable_library_ordinals(library_num - 1)
            max_ordinal = idaapi.get_ordinal_count(selected_library)
        print("[DEBUG] Maximal ordinal of lib {0} = {1}".format(selected_library.name, max_ordinal))
        return selected_library, max_ordinal, library_num == 0

def create_type(name: str, declaration: str) -> bool:
    tif = idaapi.tinfo_t()
    if tif.get_named_type(None, name):
        print("[ERROR] Type with name '{}' already exists".format(name))
        return False
    idaapi.idc_parse_types(declaration, 0)
    if not tif.get_named_type(None, name):
        print("[ERROR] Failed to create type '{}'".format(name))
        return False
    return True

def import_type(library, name):
    last_ordinal = idaapi.get_ordinal_count(idaapi.get_idati())
    type_id = idc.import_type(library, -1, name)  # tid_t
    if type_id != idaapi.BADORD:
        return last_ordinal
