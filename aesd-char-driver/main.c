/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include "aesdchar.h"

#define BUFFER_SIZE 128

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Kelan Ige");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t offset = 0;
    size_t remaining_bytes = 0;
    struct aesd_buffer_entry* entry = NULL;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    if (mutex_lock_interruptible(&aesd_device.buffer_mutex)) {
        mutex_unlock(&aesd_device.buffer_mutex);
        return -ERESTARTSYS;
    }
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&aesd_device.buffer, *f_pos, &offset);
    if (entry == NULL) {
        mutex_unlock(&aesd_device.buffer_mutex);
        return 0;
    }
    remaining_bytes = copy_to_user(buf, entry->buffptr + offset, entry->size - offset);
    retval = entry->size - remaining_bytes - offset;
    mutex_unlock(&aesd_device.buffer_mutex);
    if (remaining_bytes > 0) {
        return -EFAULT;
    }
    *f_pos += retval;
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    char* user_buf = NULL;
    int has_newline = 0;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    // Copy user buffer to kernel memory.
    user_buf = kmalloc(count, GFP_KERNEL);
    if (copy_from_user(user_buf, buf, count)) {
        kfree(user_buf);
        return -EFAULT;
    }
    if (mutex_lock_interruptible(&aesd_device.buffer_mutex)) {
        kfree(user_buf);
        mutex_unlock(&aesd_device.buffer_mutex);
        return -ERESTARTSYS;
    }

    has_newline = (strchr(user_buf, '\n') != NULL);
    if (aesd_device.string == NULL) {
        aesd_device.string = kmalloc(BUFFER_SIZE, GFP_KERNEL);
        memset(aesd_device.string, 0, BUFFER_SIZE);
        aesd_device.string_size = 0;
        aesd_device.string_capacity = BUFFER_SIZE;
    }
    if (aesd_device.string_size + count > aesd_device.string_capacity) {
        const size_t new_size = 2 * aesd_device.string_capacity;
        aesd_device.string = krealloc(aesd_device.string, new_size, GFP_KERNEL);
        aesd_device.string_capacity = new_size;
    }
    memcpy(&aesd_device.string[aesd_device.string_size], user_buf, count);
    aesd_device.string_size += count;

    if (has_newline == 1) {
        struct aesd_buffer_entry entry;
        entry.buffptr = aesd_device.string;
        entry.size = aesd_device.string_size;

        aesd_device.string = NULL;
        aesd_device.string_size = 0;
        aesd_device.string_capacity = 0;
        *f_pos += entry.size;
        if (aesd_device.buffer.full) {
            size_t offset;
            struct aesd_buffer_entry* entry = aesd_circular_buffer_find_entry_offset_for_fpos(&aesd_device.buffer, 0, &offset);
            kfree(entry->buffptr);
        }
        aesd_circular_buffer_add_entry(&aesd_device.buffer, entry);
    }
    mutex_unlock(&aesd_device.buffer_mutex);
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    aesd_device.string = NULL;
    aesd_device.string_size = 0;
    aesd_device.string_capacity = 0;
    mutex_init(&aesd_device.buffer_mutex);
    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    if (!mutex_lock_interruptible(&aesd_device.buffer_mutex)) {
        size_t index;
        struct aesd_buffer_entry* entry;
        AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
            kfree(entry->buffptr);
        }
    }
    mutex_unlock(&aesd_device.buffer_mutex);

    if (!mutex_lock_interruptible(&aesd_device.buffer_mutex)) {
        if (aesd_device.string != NULL) {
            kfree(aesd_device.string);
        }
    }
    mutex_unlock(&aesd_device.buffer_mutex);

    mutex_destroy(&aesd_device.buffer_mutex);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
