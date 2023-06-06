/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include "kshram.h"

#define DEVICE_NUM 8

struct my_cdev {
	struct cdev c_dev;
	void *private_data;
	size_t data_size;
};

static dev_t devnum;
static struct my_cdev c_dev[DEVICE_NUM];
struct class *clazz;

static int kshram_dev_open(struct inode *i, struct file *f) {
	// printk(KERN_INFO "kshram: device opened.\n");
	return 0;
}

static int kshram_dev_close(struct inode *i, struct file *f) {
	// printk(KERN_INFO "kshram: device closed.\n");
	return 0;
}

static ssize_t kshram_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	// printk(KERN_INFO "kshram: read %zu bytes @ %llu.\n", len, *off);
	return len;
}

static ssize_t kshram_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	// printk(KERN_INFO "kshram: write %zu bytes @ %llu.\n", len, *off);
	return len;
}

static long kshram_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	if (cmd == KSHRAM_GETSLOTS) {
		return 8;
	} else if (cmd == KSHRAM_GETSIZE) {
		// convert file to inode -> get device from the inode -> use the device's minor number as index
		return c_dev[MINOR(file_inode(fp)->i_cdev->dev)].data_size;
	} else if (cmd == KSHRAM_SETSIZE) {
		// realloc the memory
		c_dev[MINOR(file_inode(fp)->i_cdev->dev)].private_data = krealloc(c_dev[MINOR(file_inode(fp)->i_cdev->dev)].private_data, arg, GFP_KERNEL);
		c_dev[MINOR(file_inode(fp)->i_cdev->dev)].data_size = arg;
	}
	return 0;
}

static int kshram_dev_mmap(struct file *fp, struct vm_area_struct *vma) {
	unsigned long pfn = page_to_pfn(virt_to_page(c_dev[MINOR(file_inode(fp)->i_cdev->dev)].private_data));
	unsigned long size = vma->vm_end - vma->vm_start;
	printk(KERN_INFO "kshram/mmap: idx %d size %ld\n", MINOR(file_inode(fp)->i_cdev->dev), size);
	return remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
}

static const struct file_operations kshram_dev_fops = {
	.owner = THIS_MODULE,
	.open = kshram_dev_open,
	.read = kshram_dev_read,
	.write = kshram_dev_write,
	.unlocked_ioctl = kshram_dev_ioctl,
	.release = kshram_dev_close,
	.mmap = kshram_dev_mmap
};

static int kshram_proc_read(struct seq_file *m, void *v) {
	char buf[] = "00: %d\n01: %d\n02: %d\n03: %d\n04: %d\n05: %d\n06: %d\n07: %d\n";
	seq_printf(m, buf, c_dev[0].data_size, c_dev[1].data_size, c_dev[2].data_size, c_dev[3].data_size, 
				c_dev[4].data_size, c_dev[5].data_size, c_dev[6].data_size, c_dev[7].data_size);
	return 0;
}

static int kshram_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, kshram_proc_read, NULL);
}

static const struct proc_ops kshram_proc_fops = {
	.proc_open = kshram_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *kshram_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init kshram_init(void)
{
	// register 8 char dev from kernel, and  
	if(alloc_chrdev_region(&devnum, 0, DEVICE_NUM, "kshram_dev") < 0)
		return -1;

	// register a class for these 8 device
	if((clazz = class_create(THIS_MODULE, "kshram_class")) == NULL)
		goto release_region;
	
	// specify the ownership and permission of the device when it is created 
	clazz->devnode = kshram_devnode;


	// create multiple devices in a driver with the same major number
	for (int i = 0; i < DEVICE_NUM; i++) {
		// MAJOR(devnum) -> get major number from the device
		// MKDEV(MAJOR(devnum), i) -> create a device identifier with major and minor number
		dev_t my_device = MKDEV(MAJOR(devnum), i);
		if(device_create(clazz, NULL, my_device, NULL, "kshram%d", i) == NULL)
			goto release_class;
		cdev_init(&c_dev[i].c_dev, &kshram_dev_fops);
		c_dev[i].private_data = kzalloc(4096, GFP_KERNEL);
		SetPageReserved(virt_to_page(c_dev[i].private_data));
		c_dev[i].data_size = 4096;
		if(cdev_add(&c_dev[i].c_dev, my_device, 1) == -1)
			goto release_device;

		printk(KERN_INFO "kshram%d: 4096 bytes allocated @ %llx\n", i, (long long)(c_dev[i].private_data));
	}

	// create proc
	proc_create("kshram", 0, NULL, &kshram_proc_fops);

	printk(KERN_INFO "kshram: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	// destroy all the devices
	for (int i = 0; i < DEVICE_NUM; i++) {
		cdev_del(&c_dev[i].c_dev);
		ClearPageReserved(virt_to_page(c_dev[i].private_data));
		kfree(c_dev[i].private_data);
		c_dev[i].data_size = 0;
		device_destroy(clazz, MKDEV(MAJOR(devnum), i));
	}
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, DEVICE_NUM);
	return -1;
}

static void __exit kshram_cleanup(void)
{
	remove_proc_entry("kshram", NULL);

	for (int i = 0; i < DEVICE_NUM; i++) {
		cdev_del(&c_dev[i].c_dev);
		ClearPageReserved(virt_to_page(c_dev[i].private_data));
		kfree(c_dev[i].private_data);
		c_dev[i].data_size = 0;
		device_destroy(clazz, MKDEV(MAJOR(devnum), i));
	}
	class_destroy(clazz);
	unregister_chrdev_region(devnum, DEVICE_NUM);

	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(kshram_init);
module_exit(kshram_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
