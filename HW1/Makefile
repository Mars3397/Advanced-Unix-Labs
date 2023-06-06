CC		= gcc
CFLAGS	= -Wall -g -D_GNU_SOURCE -fPIC
PROGS	= sandbox.so

all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

sandbox.so: sandbox.o
	$(CC) -o $@ -shared $^

tar:
	tar -czvf 109550018_hw1.tar.gz Makefile sandbox.c

clean:
	rm -f $(PROGS) *.o
	rm -f index.html*
	rm -f *.log

# gdb --args ./launcher ./sandbox.so config.txt cat /etc/passwd