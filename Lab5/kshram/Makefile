obj-m     += kshram.o
ccflags-y += -DEXPORT_SYMTAB

all:
	make -C ../dist/modulebuild M=$(PWD) modules

clean:
	rm -f kshram
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	cp kshram.ko ../dist/rootfs

# cd ../dist/rootfs; find . | cpio -H newc -o | bzip2 > ../newrootfs.cpio.bz2; cd ../..; ./qemu.sh
