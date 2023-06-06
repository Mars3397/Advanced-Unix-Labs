#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[16] = "hello, world!";

	for (int i = 0x18; i <= 0x30; i+=8) {
		fptr("%016lx\n", *(unsigned long *)&msg[i]);
	}
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}

