# Copyright (C) 2022 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

""" 
------------------
| Encoding Module |
------------------
This module includes encoding functions which can be called by other classes. 

ENCODING FUNCTIONS
    Descr:      Functions used primarily to operate on SearchTerm objects. Defined input/output.
    Find:       Encoder.list(encoders=True)
    Add:        ENCODER_LIST dictionary
    Accepts:    byte strings
    Returns:    list of byte strings

UTIL FUNCTIONS
    Descr:      General utility/encoding functions. Don't have defined input/output types.
    Find:       Encoder.list(utils=True)
    Add:        UTIL_LIST dictionary. Preface func name with util_
    Accepts:    varies
    Returns:    varies
"""

from base64 import b64encode 
from chardet import detect
from re import sub
from sys import stderr
from typing import Callable, Union

""" 
------------
| ENCODERS |
------------
"""
def base64(val: bytes) -> list[bytes]:
    ## Encode provided val as Base64 with various offsets
    
    # Calc off0 B64 and remove any variable characters
    off0 = b64encode(val).decode('ascii')
    off0 = off0[0:off0.find('=')-1] if '=' in off0 else off0

    # Calc off1 B64 and remove any variable characters
    temp = b'\x00' + val
    off1 = b64encode(temp).decode('ascii')[2:]
    off1 = off1[0:off1.find('=')-1] if '=' in off1 else off1

    # Calc off2 B64 and remove any variable characters
    temp = b'\x00' + temp
    off2 = b64encode(temp).decode('ascii')[3:]
    off2 = off2[0:off2.find('=')-1] if '=' in off2 else off2

    # The most minimal of safety checking
    if len(off0) < 4 or len(off1) < 4 or len(off2) < 4:
        print("[*] WARNING - 1 or more terms is shorter than 4 characters. This may result in a resource intensive rule.", file=stderr)

    # Return list of byte strings with Base64 encoded input at offset 0, 1, and 2
    return [off0.encode('utf-8'), off1.encode('utf-8'), off2.encode('utf-8')]


def plain(val: bytes) -> list[bytes]:
    ## Return the original value
    return [val]

def reverse(val: bytes) -> list[bytes]:
    ## Return the original value
    return [reversed(val)]

def utf8(val: bytes) -> list[bytes]:
    ## Return UTF8 encoded values
    if isinstance(val, str):
        return [val.encode('utf-8')]
    else:
        return [val.decode(detect(val)['encoding']).encode('utf-8')]

def utf16le(val: bytes) -> list[bytes]:
    ## Return UTF16LE encoded values
    if isinstance(val, str):
        return [val.encode('utf-16le')]
    else:
        return [val.decode(detect(val)['encoding']).encode('utf-16le')]

""" 
-------------
| UTILITIES |
-------------
"""
def util_raw_hex(val: Union[bytes, str]) -> str:
    ## Return an ASCII string with the \x formatted bytes from input
    ## Useful for rule outputs that don't support UTF encoding

    val = bytes(val, "ascii") if isinstance(val, str) else val
    return "".join(["\\x{:02x}".format(char) for char in val])

def util_strip_special(val: Union[bytes, str]) -> str:
    ## Return object without special characters. 
    ## Useful for rule/file names
    pattern = b"\W+" if isinstance(val, bytes) else "\W+"
    repl = b"" if isinstance(val, bytes) else ""
    return sub(pattern, repl, val)

""" 
----------------
| GLOBAL LISTS |
----------------
"""
#General encoding functions. Taken from heyserial
ENCODER_LIST = {
    'base64': base64,
    'plain': plain,
    'reverse': reverse,
    'utf8': utf8,
    'utf16le': utf16le
}

#Utils are technically encoders but just for cleaning up output and stuff
UTIL_LIST = {
    'raw_hex': util_raw_hex,
    'strip_special': util_strip_special
}

""" 
----------------
| GETTER FUNCS |
----------------
"""
def list(encoders: bool = True, utils: bool = False) -> list[str]:
    ## List names of all available encoder and/or util funcs
    funcs = []

    if encoders:
        funcs = [*ENCODER_LIST]
    if utils:
        funcs.extend([*UTIL_LIST])

    return funcs

def lookup(val: str, isutil: bool = True):
    ## Return function reference for provided name

    if isutil and val in UTIL_LIST.keys():
        return UTIL_LIST[val]

    elif val in ENCODER_LIST.keys():
        return ENCODER_LIST[val]
    
    else:
        print(f"[!] WARNING No encoding function found for {val}", file=stderr)
        return None
