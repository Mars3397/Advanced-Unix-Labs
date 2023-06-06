
obj-m     += hellomod.o
ccflags-y += -DEXPORT_SYMTAB

all: hello
	make -C ../dist/modulebuild M=$(PWD) modules

hello: hello.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f hello
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
# mkdir -p ../rootfs/modules
	cp hello hellomod.ko ../dist/rootfs
	
# cd ../dist/rootfs
# find . | cpio -H newc -o | bzip2 > ../newrootfs.cpio.bz2
# cd ../../hellomod
