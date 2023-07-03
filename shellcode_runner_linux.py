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

__version__ = "0.0.1"
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

import ctypes
import mmap

shellcode = b"hed \x0b\x814$\x01\x01\x01\x01H\xb8 shellcoPH\xb8rld fromPH\xb8Hello WoPj\x01Xj\x01_j\x1cZH\x89\xe6\x0f\x05XXXX\xc3"
mem = mmap.mmap(
    -1,
    mmap.PAGESIZE,
    mmap.MAP_SHARED,
    mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
)
mem.write(shellcode)
addr = int.from_bytes(ctypes.string_at(id(mem) + 16, 8), "little")
print(hex(addr))
functype = ctypes.CFUNCTYPE(ctypes.c_void_p)
fn = functype(addr)
fn()
print("Back to python!")