#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

#define errquit(m)	{ perror(m); _exit(-1); }

void intToByteArray(int value, unsigned char* array, int size) {
    // convert int to ascii byte array
    for (int i = 0; i < size; ++i) {
        array[i] = (value % 2) + 0x30;
        value /= 2;
    }

    // reverse the array
    int start = 0, end = size - 1;
    while (start < end) {
        int temp = array[start];
        array[start] = array[end];
        array[end] = temp;
        start++; end--;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s program\n", argv[0]);
        return -1;
    }

    pid_t child;
    if ((child = fork()) < 0) errquit("fork");
    
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("fork");
        execvp(argv[1], argv + 1);
        errquit("execvp");
    } else {
        int status;
        int magic = 1, f = 0;
        struct user_regs_struct regs, copy_regs;
        long magic_addr = 0;
        if (waitpid(child, &status, 0) < 0) errquit("wait");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        // get magic_addr and snapshot the registers
        while (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                long rax = regs.rax;
                // snapshot after connect and before reset
                if (f) {
                    if (ptrace(PTRACE_GETREGS, child, 0, &copy_regs) != 0) errquit("snapshot");
                    copy_regs.rip = copy_regs.rip - 1;
                    f = 0;
                }

                // get the address of magic
                if (rax != 0 && rax != 0xffffffff) {
                    magic_addr = rax;
                    f = 1;
                } 
                // fail for oracle_get_flag -> restore the registers
                else if (rax == 0xffffffff) {
                    if (ptrace(PTRACE_SETREGS, child, 0, &copy_regs) != 0) errquit("setregs");
                    if (ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
                    if (waitpid(child, &status, 0) < 0) errquit("wait");
                    break;
                }
            } 

            // continue to next break point
            if (ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
            if (waitpid(child, &status, 0) < 0) errquit("wait");
        }

        // try all
        while (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                long rax = regs.rax;

                // fail for oracle_get_flag -> restore the registers
                if (rax == 0xffffffff) {
                    if (ptrace(PTRACE_SETREGS, child, 0, &copy_regs) != 0) errquit("setregs");
                    magic++;
                } 
                // modify magic and continue to next break point
                else {
                    unsigned char data1[11];
                    intToByteArray(magic, data1, 9);
                    data1[9] = 0x30; data1[10] = 0x30;
                    unsigned long *pdata1 = (unsigned long *)data1, *pdata2 = (unsigned long *)(data1 + 8);
                    if (ptrace(PTRACE_POKETEXT, child, magic_addr, *pdata1) != 0) errquit("poketext");
                    if (ptrace(PTRACE_POKETEXT, child, magic_addr + 8, *(pdata2)) != 0) errquit("poketext");
                    if (ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
                    if (waitpid(child, &status, 0) < 0) errquit("wait");
                }
            } 

            // continue to next break point
            if (ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
            if (waitpid(child, &status, 0) < 0) errquit("wait");

            // break when magic exceeds 512
            if (magic > 512) break;
        }
    }

    return 0;
}
