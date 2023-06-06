#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <capstone/capstone.h>

#define errquit(m)	{ perror(m); _exit(-1); }
#define PEEKSIZE 8
#define NUM_BREAKS 20

// struct breakpoint for breakpoints array
struct breakpoint {
    int reached;
    unsigned long long addr;
    unsigned char original_content[8];
    unsigned char patched_content[8];
};

// struct anchor data to store anchor infomation
struct anchor_data {
    int used;
    unsigned char *memory;
    long memory_min, memory_max;
    unsigned char *stack;
    long stack_min, stack_max;
    unsigned char *heap;
    long heap_min, heap_max;
    struct user_regs_struct regs;
};

// define anchor and breakpoints array
struct anchor_data anchor;
struct breakpoint breakpoints[NUM_BREAKS];

// capstone handler
static csh cshandle = 0;

// compare function for qsort
int compareByAddr(const void* a, const void* b) {
    const struct breakpoint* breakpointA = (const struct breakpoint*)a;
    const struct breakpoint* breakpointB = (const struct breakpoint*)b;

    if (breakpointA->addr < breakpointB->addr) return -1;
    else if (breakpointA->addr > breakpointB->addr) return 1;
    else return 0;
}

// get the size of text to know the bound of codes
unsigned long long get_text_size(const char file[]) {
    // execute readelf command and get the output
    char command[128];
    sprintf(command, "readelf -S %s | grep -A1 .text", file);

    FILE* pipe = popen(command, "r");
    if (pipe == NULL) errquit("popen")

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {}
    pclose(pipe);

    // retrieve the size of text segment and convert to long
    const char delimiter[] = " ";
    char *token = strtok(buffer, delimiter);

    return strtoll(token, NULL, 16);
}

// function that store info in an anchor
static void set_anchor(pid_t child) {
    // set memory content (memory, stack, heap) in /proc/pid/maps
	int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
    char maps_file[25];
    sprintf(maps_file, "/proc/%d/maps", child);
	if((fd = open(maps_file, O_RDONLY)) < 0) errquit("set_anchor/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("set_anchor/read");
	buf[sz] = 0;
	close(fd);
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
        if (strstr(line, " rwxp ") || strstr(line, " rw-p ")) {
            long min, max, peek;
            if(sscanf(line, "%lx-%lx ", &min, &max) != 2) errquit("set_anchor/sscanf");
            long size = max - min; 

            // store stack content in anchor
            if (strstr(line, "[stack]")) {
                anchor.stack_min = min;
                anchor.stack_max = max;
                anchor.stack = (unsigned char*)realloc(anchor.stack, size * sizeof(unsigned char));
                for (unsigned long long ptr = min; ptr < max; ptr += PEEKSIZE) {
                    errno = 0;
                    long long peek = ptrace(PTRACE_PEEKTEXT, child, ptr, NULL);
                    if(errno != 0) break;
                    memcpy(&anchor.stack[ptr-min], &peek, PEEKSIZE);
                }
            } 
            // store heap content in anchor
            else if (strstr(line, "[heap]")) {
                anchor.heap_min = min;
                anchor.heap_max = max;
                anchor.heap = (unsigned char*)realloc(anchor.heap, size * sizeof(unsigned char));
                for (unsigned long long ptr = min; ptr < max; ptr += PEEKSIZE) {
                    errno = 0;
                    long long peek = ptrace(PTRACE_PEEKTEXT, child, ptr, NULL);
                    if(errno != 0) break;
                    memcpy(&anchor.heap[ptr-min], &peek, PEEKSIZE);
                }
            } 
            // store rw-p content in anchor
            else {
                anchor.memory_min = min;
                anchor.memory_max = max;
                anchor.memory = (unsigned char*)realloc(anchor.memory, size * sizeof(unsigned char));
                for (unsigned long long ptr = min; ptr < max; ptr += PEEKSIZE) {
                    errno = 0;
                    long long peek = ptrace(PTRACE_PEEKTEXT, child, ptr, NULL);
                    if(errno != 0) break;
                    memcpy(&anchor.memory[ptr-min], &peek, PEEKSIZE);
                }
            }
        }
	}

    // set registers
    if (ptrace(PTRACE_GETREGS, child, 0, &anchor.regs) != 0) errquit("set_anchor/getregs")
    anchor.used = 1;

	return;
}

void timetravel(pid_t child) {
    // restore writable memory content
    for (unsigned long long ptr = anchor.stack_min; ptr < anchor.stack_max; ptr += PEEKSIZE) {
        if (ptrace(PTRACE_POKETEXT, child, ptr, *(unsigned long *)(anchor.stack + (ptr-anchor.stack_min))) != 0) errquit("poketext");
    }
    for (unsigned long long ptr = anchor.heap_min; ptr < anchor.heap_max; ptr += PEEKSIZE) {
        if (ptrace(PTRACE_POKETEXT, child, ptr, *(unsigned long *)(anchor.heap + (ptr-anchor.heap_min))) != 0) errquit("poketext");
    }
    for (unsigned long long ptr = anchor.memory_min; ptr < anchor.memory_max; ptr += PEEKSIZE) {
        if (ptrace(PTRACE_POKETEXT, child, ptr, *(unsigned long *)(anchor.memory + (ptr-anchor.memory_min))) != 0) errquit("poketext");
    }

    // restore regs
    if (ptrace(PTRACE_SETREGS, child, 0, &anchor.regs) != 0) errquit("timetravel/setregs");

    // restore breakpoints
    for (int i = 0; i < NUM_BREAKS; i++) {
        if (breakpoints[i].addr > anchor.regs.rip) breakpoints[i].reached = 0;
    }
}

void disassemble(pid_t child, unsigned long long rip, unsigned long long end_address) {
    int count;
	char buf[64] = { 0 };
	unsigned long long ptr = rip;
	cs_insn *insn;

    for (ptr = rip; ptr < rip + sizeof(buf); ptr += PEEKSIZE) {
		errno = 0;
		long long peek = ptrace(PTRACE_PEEKTEXT, child, ptr, NULL);
		if (errno != 0) break;
		memcpy(&buf[ptr-rip], &peek, PEEKSIZE);
	}

    if ((count = cs_disasm(cshandle, (uint8_t*) buf, ptr - rip, rip, 0, &insn)) > 0) {
        for (int i = 0; i < 5; i++) {
            char format_bytes[128] = "";
            for (int j = 0; j < insn[i].size; j++) {
                snprintf(&format_bytes[j * 3], 4, "%2.2x ", insn[i].bytes[j]);
            }

            if (insn[i].address >= end_address) {
                fprintf(stderr, "** the address is out of the range of the text segment.\n");
                break;
            }

            fprintf(stderr, "%*lx: %-32s\t%-10s%s\n", 12, insn[i].address, format_bytes, insn[i].mnemonic, insn[i].op_str);
        }
		cs_free(insn, count);
	} 

    return;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s [program]\n", argv[0]);
        return -1;
    }

    pid_t child;
    if ((child = fork()) < 0) errquit("fork");
    
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("fork");
        execvp(argv[1], argv + 1);
        errquit("execvp");
    } else {
        int status, f = 0;
        struct user_regs_struct regs;
        long long peek;
        if (waitpid(child, &status, 0) < 0) errquit("wait");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        // for disassemble library capstone
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK) errquit("cs_open");

        // get the size of text segment
        unsigned long long text_end_address = get_text_size(argv[1]);
        int is_first = 1, can_disassemble = 1, not_timetravel = 1;

        char cmd_buf[25];

        while (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                if (is_first) {
                    text_end_address += regs.rip;
                    is_first = 0;
                    printf("** program '%s' loaded. entry point 0x%llx\n", argv[1], regs.rip);
                }

                for (int i = 0; i < NUM_BREAKS; i++) {
                    if (breakpoints[i].addr == regs.rip && breakpoints[i].reached == 0) {
                        if (ptrace(PTRACE_POKETEXT, child, breakpoints[i].addr, *(unsigned long *)breakpoints[i].original_content) != 0) errquit("poketext");
                        breakpoints[i].reached = 1;
                        if (not_timetravel) {
                            printf("** hit a breakpoint 0x%llx\n", regs.rip);
                        } else {
                            not_timetravel = 1;
                        }
                        break;
                    }
                }

                // restore original bytes at break points before disassemble
                for (int i = 0; i < NUM_BREAKS; i++) {
                    if (breakpoints[i].addr == 0 || breakpoints[i].reached == 1) continue;
                    if (ptrace(PTRACE_POKETEXT, child, breakpoints[i].addr, *(unsigned long *)breakpoints[i].original_content) != 0) errquit("poketext");
                }

                if (can_disassemble) {                  
                    disassemble(child, regs.rip, text_end_address);
                }

                // add patched bytes back to break points after disassemble
                for (int i = 0; i < NUM_BREAKS; i++) {
                    if (breakpoints[i].addr == 0 || breakpoints[i].reached == 1) continue;
                    if (ptrace(PTRACE_POKETEXT, child, breakpoints[i].addr, *(unsigned long *)breakpoints[i].patched_content) != 0) errquit("poketext");
                }
            } 

            printf("(sdb) ");
            scanf(" %24[^\n]", cmd_buf);

            // for a command which is not si, cont, timetravel, the debugger should not disassemble the program
            if (strcmp(cmd_buf, "cont") != 0 && strcmp(cmd_buf, "si") != 0 && strcmp(cmd_buf, "timetravel") != 0) 
                can_disassemble = 0;
            else 
                can_disassemble = 1;

            // command == cont
            if (strcmp(cmd_buf, "cont") == 0) {
                if (ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
                if (waitpid(child, &status, 0) < 0) errquit("wait");
                if (WIFSTOPPED(status)) {
                    if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("getregs");
                    regs.rip--;
                    if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("setregs");
                }
                not_timetravel = 1;
            } 
            // command == si
            else if (strcmp(cmd_buf, "si") == 0) {
                if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("ptrace@parent");
                if (waitpid(child, &status, 0) < 0) errquit("wait");
                not_timetravel = 1;
            }
            // command == break <address in hexdecimal>
            else if (strncmp(cmd_buf, "break ", 6) == 0) {
                printf("** set a breakpoint at %s\n", (char *)(cmd_buf + 6));
                unsigned long long break_addr = strtoll(cmd_buf + 8, NULL, 16);
                for (int i = 0; i < NUM_BREAKS; i++) {
                    if (breakpoints[i].addr == 0) {
                        breakpoints[i].addr = break_addr;
                        errno = 0;
                        peek = ptrace(PTRACE_PEEKTEXT, child, break_addr, NULL);
                        if (errno != 0) errquit("peek");
                        unsigned char cc[8];
                        memcpy(&cc, &peek, PEEKSIZE);
                        memcpy(&breakpoints[i].original_content, &cc, PEEKSIZE);
                        cc[0] = 0xcc;
                        memcpy(&breakpoints[i].patched_content, &cc, PEEKSIZE);
                        if (ptrace(PTRACE_POKETEXT, child, break_addr, *(unsigned long *)cc) != 0) errquit("poketext");
                        break;
                    }
                }
                qsort(breakpoints, NUM_BREAKS, sizeof(struct breakpoint), compareByAddr);
                not_timetravel = 0;
            }
            // command == anchor
            else if (strcmp(cmd_buf, "anchor") == 0) {
                printf("** dropped an anchor\n");
                set_anchor(child);
                not_timetravel = 1;
            }
            // command == timetravel
            else if (strcmp(cmd_buf, "timetravel") == 0) {
                printf("** go back to the anchor point\n");
                timetravel(child);
                not_timetravel = 0;
            }
        }
    }

    printf("** the target program terminated.\n");

    return 0;
}