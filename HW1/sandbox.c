#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <elf.h>
#include <sys/mman.h>
#include <limits.h>

#define PAGE_SIZE getpagesize()
#define BOOL int
#define TRUE 1
#define FALSE 0
#define log_fd atoi(getenv("LOGGER_FD"))

// Error handler
#define errquit(m)	{ perror(m); _exit(-1); }
static long main_min = 0, main_max = 0;

// Function pointers to the real API functions
static int (*real_open)(const char *, int, mode_t) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static ssize_t (*real_write)(int, const void *, size_t) = NULL;
static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
static int (*real_system)(const char *) = NULL;
static int (*real_libc_start_main)(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (*stack_end)) = NULL;
static int (*my_open_ptr)(const char *, int, mode_t) = NULL;
static ssize_t (*my_read_ptr)(int, void *, size_t) = NULL;
static ssize_t (*my_write_ptr)(int, const void *, size_t) = NULL;
static int (*my_connect_ptr)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*my_getaddrinfo_ptr)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
static int (*my_system_ptr)(const char *) = NULL;

// get blacklist content for each function
char* get_blacklist_content(char func_name[]) {
    FILE* file = fopen(getenv("SANDBOX_CONFIG"), "r");
    if (file == NULL) {
        errquit("Could not open config.txt\n");
    }

    int MAX_LINE_LENGTH = 128;
    char line[MAX_LINE_LENGTH];
    char *blacklist_content = NULL;
    int blacklist_content_len = 0;
    BOOL in_blacklist_section = FALSE;
    char content_begin[30], content_end[30];
    strcpy(content_begin, "BEGIN ");        strcpy(content_end, "END ");
    strcat(content_begin, func_name);       strcat(content_end, func_name);
    strcat(content_begin, "-blacklist");    strcat(content_end, "-blacklist");

    while (fgets(line, MAX_LINE_LENGTH, file)) {
        if (strstr(line, content_begin)) {
            in_blacklist_section = TRUE;
        } else if (strstr(line, content_end)) {
            in_blacklist_section = FALSE;
            break;
        } else if (in_blacklist_section) {
            size_t line_len = strlen(line);
            char* new_content = realloc(blacklist_content, blacklist_content_len + line_len + 1);
            if (new_content == NULL) {
                errquit("Memory allocation failed\n");
            }
            blacklist_content = new_content;
            strcpy(blacklist_content + blacklist_content_len, line);
            blacklist_content_len += line_len;
        }
    }

    fclose(file);
    return blacklist_content;
}

// get the base address of a exec_file
static void get_base(char *exec_file) {
	int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
		// if(strstr(line, " r--p ") == NULL) continue;
		if(strstr(line, exec_file) != NULL) {
			if(sscanf(line, "%lx-%lx ", &main_min, &main_max) != 2) errquit("get_base/main");
		} 
		if(main_min != 0 && main_max != 0) return;
	}
	_exit(-fprintf(stderr, "** get_base failed.\n"));
}

// get the link file from a path (the path should be a symbolic link)
char* get_link_path(char *path) {
    struct stat sb;
    char *buf;
    ssize_t nbytes, bufsiz;

    if (lstat(path, &sb) == -1) errquit("get_link_path/lstat");

    bufsiz = sb.st_size + 1;
    if (sb.st_size == 0) bufsiz = PATH_MAX;

    buf = malloc(bufsiz);
    if (buf == NULL) errquit("get_link_path/malloc");

    nbytes = readlink(path, buf, bufsiz);
    if (nbytes == -1) errquit("get_link_path/readlink");

    if (nbytes == bufsiz) printf("(Returned buffer may have been truncated)\n");

    return buf;
}

// check whether the hostname match a ip
BOOL hostname_match_ip(char *hostname, char connect_ip[]) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int ret;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0; 

    // Resolve the hostname to a list of addresses
    ret = getaddrinfo(hostname, NULL, &hints, &result);
    if (ret != 0) {
        errquit("hostname_match_ip/getaddrinfo");
    }

    /* Loop through the list of addresses and print the IP addresses */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char ip[INET_ADDRSTRLEN];
        void *addr;

        struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
        addr = &(ipv4->sin_addr);

        inet_ntop(rp->ai_family, addr, ip, sizeof(ip));
        if (strcmp(connect_ip, ip) == 0) {
            freeaddrinfo(result);
            return TRUE;
        }
    }

    freeaddrinfo(result);
    return FALSE;
}

// replace a char in a string to another
char* replace_char(char str[], char find, char replace){
    for (int i = 0; i < strlen(str); i++) {
        if (str[i] == find) {
            str[i] = replace;
        }
    }
    return str;
}

// fin whether a strig is in a file or not
BOOL find_string_in_file(char *string, char *file) {
    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        errquit("find_string_in_file/fopen");
    }
    // get file size
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buf = (char *)malloc(size + 1);
    if (buf == NULL) {
        fclose(fp);
        errquit("find_string_in_file/malloc");
    }

    fread(buf, size, 1, fp);
    buf[size] = '\0';
    fclose(fp);

    // check wehter a string is in the file
    if (strstr(buf, string)) {
        free(buf);
        return TRUE;
    } else {
        free(buf);
        return FALSE;
    }
}

// Define the hijacked functions
// * my_open()
int my_open(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    // check the use of mode by flag
    if (flags == O_CREAT || flags == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
    }

    // handle if the pathname is symbolic link
    char* file_path = malloc(strlen(pathname) + 1);
    strcpy(file_path, pathname);
    struct stat buf;
    lstat(pathname, &buf);
    // the file path is the path of a link
    if (S_ISLNK(buf.st_mode)) {
        char *link_path = get_link_path(file_path);
        file_path = realloc(file_path, strlen(link_path) + 1);
        strcpy(file_path, link_path);
    }

    // Get the blacklist cotent for open()
    char *content_ptr = get_blacklist_content("open"), *path;
    path = strtok(content_ptr, "\n");

    // iterate through blacklist content
    while (path != NULL) {
        // Convert the file_path to absolute path
        char real_path[PATH_MAX];
        char *res = realpath(path, real_path);
        if (res != NULL) {
            // handle if the blacklist path is symbolic link
            struct stat buffer;
            lstat(path, &buffer);
            if (S_ISLNK(buffer.st_mode)) {
                char *link_path = get_link_path(real_path);
                strcpy(real_path, link_path);
            }
            // compare the file path and the path in blacklist
            if (strcmp(real_path, file_path) == 0) {
                // logger
                dprintf(log_fd, "[logger] open(\"%s\", %d, %d) = -1\n", file_path, flags, mode);
                // set error number
                errno = EACCES;
                return -1;
            }
        }
        path = strtok(NULL, "\n");		   
    }
    int open_fd = real_open(file_path, flags, mode);
    // logger
    dprintf(log_fd, "[logger] open(\"%s\", %d, %d) = %d\n", file_path, flags, mode, open_fd);
    free(file_path);
    return open_fd;
}

// * my_read()
ssize_t my_read(int fd, void *buf, size_t count) {
    ssize_t ret = real_read(fd, buf, count);
    char *content_ptr = get_blacklist_content("read");
    // get the file that the fd is point to
    FILE *fp = popen("ls -l /proc/$$/fd/", "r");
    if (fp == NULL) {
        errquit("my_read/popen");
    }

    char command_output[4096], search[40];
    snprintf(search, 40, "%d -> ", fd);
    while (fgets(command_output, sizeof(command_output), fp) != NULL) {
        char *ptr = strstr(command_output, search);
        if (ptr != NULL) {
            char *target_file = ptr + strlen(search), record_file[PATH_MAX];
            snprintf(record_file, PATH_MAX, "%d-read", getpid());
            strcat(record_file, target_file);
            strcat(record_file, ".log");
            char *temp_file = replace_char(record_file, '/', '-');
            // write the read content to a temp file for futher check
            FILE *out_file = fopen(temp_file, "a");
            fprintf(out_file, buf, count);
            fclose(out_file);
            // check the read content 
            if (find_string_in_file(content_ptr, temp_file)) {
                remove(temp_file);
                pclose(fp); close(fd);
                dprintf(log_fd, "[logger] read(%d, %p, %ld) = -1\n", fd, buf, count);
                errno = EIO;
                return -1;
            }
        }
    }

    pclose(fp);

    if (ret > 0) {
        // write read content to log file
        char read_log[30];
        snprintf(read_log, 30, "%d-%d-read.log", getpid(), fd);
        FILE *out_file = fopen(read_log, "a");
        fprintf(out_file, buf, count);
        fclose(out_file);
    }
    
    dprintf(log_fd, "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, ret);
    return ret;
}

// * my_write()
ssize_t my_write(int fd, const void *buf, size_t count) {
    // wrtie the content to log file
    char write_log[30];
    snprintf(write_log, 30, "%d-%d-write.log", getpid(), fd);
    FILE *out_file = fopen(write_log, "a");
    fprintf(out_file, buf, count);
    fclose(out_file);
    
    int ret = real_write(fd, buf, count);
    // logger
    dprintf(log_fd, "[logger] write(%d, %p, %ld) = %d\n", fd, buf, count, ret);
    return ret;
}

// * my_connect()
int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char *content_ptr = get_blacklist_content("connect");
    
    // get ip address and port number from addr
    char connect_ip[addrlen];
    struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
    inet_ntop(AF_INET, &(addr4->sin_addr), connect_ip, addrlen);
    int port = ntohs(addr4->sin_port);
    
    // iterate through blacklist content
    char *content, *saveptr = NULL;
    content = strtok_r(content_ptr, "\n", &saveptr);
    while (content != NULL) {
        // split out the IP address and port number from balcklist
        char *copy, *hostname;
        copy = malloc(strlen(content) + 1);
        strcpy(copy, content);
        hostname = strtok(copy, ":");
        int bport = atoi(strtok(NULL, ":"));
        if (hostname_match_ip(hostname, connect_ip) && port == bport) {
            // logger
            dprintf(log_fd, "[logger] connect(%d, \"%s\", %d) = -1\n", sockfd, connect_ip, addrlen);
            free(copy);	
            // set error number
            errno = ECONNREFUSED;
            return -1;
        }
        content = strtok_r(NULL, "\n", &saveptr);
        free(copy);		   
    }

    int ret = real_connect(sockfd, addr, addrlen);
    // logger
    dprintf(log_fd, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, connect_ip, addrlen, ret);
    return ret;
}

// * my_getaddrinfo()
int my_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    char *content_ptr = get_blacklist_content("getaddrinfo"), *host;
    host = strtok(content_ptr, "\n");

    // iterate through blacklist content
    while (host != NULL) {
        if (strcmp(host, node) == 0) {
            // logger
            dprintf(log_fd, "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = -2\n", node, service, hints, res);
            return EAI_NONAME;
        }
        host = strtok(NULL, "\n");		   
    }

    int ret = real_getaddrinfo(node, service, hints, res);
    // logger
    dprintf(log_fd, "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %d\n", node, service, hints, res, ret);
    return ret;
}

// * my_system()
int my_system(const char *command) {
    dprintf(log_fd, "[logger] system(\"%s\")\n", command);
    return real_system(command);
}

// Initialize the function pointers to the real API functions
void init_functions_ptrs() {
    void* handle = dlopen("libc.so.6", RTLD_LAZY);
    void* handle1 = dlopen("sandbox.so", RTLD_LAZY);
    if (handle) {
        // initialize real function pointer
        real_open = dlsym(handle, "open");
        real_read = dlsym(handle, "read");
        real_write = dlsym(handle, "write");
        real_system = dlsym(handle, "system");
        real_connect = dlsym(handle, "connect");
        real_getaddrinfo = dlsym(handle, "getaddrinfo");
        real_libc_start_main = dlsym(handle, "__libc_start_main");
        // initialize my function pointer
        my_open_ptr = dlsym(handle1, "my_open");
        my_read_ptr = dlsym(handle1, "my_read");
        my_write_ptr = dlsym(handle1, "my_write");
        my_system_ptr = dlsym(handle1, "my_system");
        my_connect_ptr = dlsym(handle1, "my_connect");
        my_getaddrinfo_ptr = dlsym(handle1, "my_getaddrinfo");
    } else {
        errquit("init_real_functions failed: handle = NULL\n");
    }
}

// Perform GOT hijacking for the functions, just like what we did in lab3
void got_hijack(char *exec_file) {
    // get exec_file main base
    get_base(exec_file);

    // Open the executable file
    FILE *fp = fopen(exec_file, "rb");
    if (!fp) {
        errquit("cannot open exec_file\n");
    }

    // Read the ELF header
    Elf64_Ehdr elf_hdr;
    fread(&elf_hdr, sizeof(Elf64_Ehdr), 1, fp);

    // Read the section header table
    fseek(fp, elf_hdr.e_shoff, SEEK_SET);
    Elf64_Shdr sec_hdr_table[elf_hdr.e_shnum];
    fread(sec_hdr_table, sizeof(Elf64_Shdr), elf_hdr.e_shnum, fp);

    // Read the string table section
    Elf64_Shdr base_str_sec_hdr = sec_hdr_table[elf_hdr.e_shstrndx];
    char *base_str_table = (char *) malloc(base_str_sec_hdr.sh_size);
    fseek(fp, base_str_sec_hdr.sh_offset, SEEK_SET);
    fread(base_str_table, base_str_sec_hdr.sh_size, 1, fp);
    
    // Find the .rela.plt section
    Elf64_Shdr rela_sec_hdr;
    for (int i = 0; i < elf_hdr.e_shnum; i++) {
        if (sec_hdr_table[i].sh_type == SHT_RELA) {
            char *name = base_str_table + sec_hdr_table[i].sh_name;
            if (strcmp(".rela.plt", name) == 0) {
                rela_sec_hdr = sec_hdr_table[i];
                break;
            }
        }
    }

    // Print the relocations
    // Get relocation symbol table
    Elf64_Shdr rela_sym_sec_hdr = sec_hdr_table[rela_sec_hdr.sh_link];
    Elf64_Sym sym_table[rela_sym_sec_hdr.sh_size / sizeof(Elf64_Sym)];
    fseek(fp, rela_sym_sec_hdr.sh_offset, SEEK_SET);
    fread(sym_table, sizeof(Elf64_Sym), rela_sym_sec_hdr.sh_size / sizeof(Elf64_Sym), fp);

    // Get relocation string table
    Elf64_Shdr rela_str_sec_hdr = sec_hdr_table[rela_sym_sec_hdr.sh_link];
    char *rela_str_table = (char *) malloc(rela_str_sec_hdr.sh_size);
    fseek(fp, rela_str_sec_hdr.sh_offset, SEEK_SET);
    fread(rela_str_table, rela_str_sec_hdr.sh_size, 1, fp);

    // Get relocation data
    Elf64_Rela rela[rela_sec_hdr.sh_size / sizeof(Elf64_Rela)];
    fseek(fp, rela_sec_hdr.sh_offset, SEEK_SET);
    fread(rela, sizeof(Elf64_Rela), rela_sec_hdr.sh_size / sizeof(Elf64_Rela), fp);

    // get the GOT offset of each function and perform GOT hijack
    for (int i = 0; i < rela_sec_hdr.sh_size / rela_sec_hdr.sh_entsize; i++) {
        Elf64_Rela *r = &rela[i];
        int symidx = ELF64_R_SYM(r->r_info);
        Elf64_Sym *sym = &sym_table[symidx];
        char *symname = rela_str_table + sym->st_name;
        if (strcmp(symname, "open") == 0 || strcmp(symname, "read") == 0 || strcmp(symname, "write") == 0 || 
            strcmp(symname, "connect") == 0 || strcmp(symname, "getaddrinfo") == 0 || strcmp(symname, "system") == 0) {
            // got addr is the base address of execute file + offset 
            long hijack_got_addr = main_min + r->r_offset;
            // Calculate the base address of the page that modify_addr current in
			long base_page = hijack_got_addr & ~(PAGE_SIZE - 1);
            // modify the permission of the page
			if (mprotect((long *)base_page, PAGE_SIZE, PROT_READ | PROT_WRITE) == -1) {
				errquit("mprotect");
			}

            // copy the correct function address to GOT entry
            if (strcmp(symname, "open") == 0) {
			    memcpy((long *)hijack_got_addr, &my_open_ptr, sizeof(long));
            } else if (strcmp(symname, "read") == 0) {
			    memcpy((long *)hijack_got_addr, &my_read_ptr, sizeof(long));
            } else if (strcmp(symname, "write") == 0) {
			    memcpy((long *)hijack_got_addr, &my_write_ptr, sizeof(long));
            } else if (strcmp(symname, "connect") == 0) {
			    memcpy((long *)hijack_got_addr, &my_connect_ptr, sizeof(long));
            } else if (strcmp(symname, "getaddrinfo") == 0) {
			    memcpy((long *)hijack_got_addr, &my_getaddrinfo_ptr, sizeof(long));
            } else {
                memcpy((long *)hijack_got_addr, &my_system_ptr, sizeof(long));
            }
        }
    }

    fclose(fp);
    free(base_str_table);
    free(rela_str_table);
}

// Implement the __libc_start_main function to hijack the process's entry point
void __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (*stack_end)) {
    // Perform necessary initializations
    init_functions_ptrs();
    got_hijack(get_link_path("/proc/self/exe"));

    // Call the original __libc_start_main()
    real_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}