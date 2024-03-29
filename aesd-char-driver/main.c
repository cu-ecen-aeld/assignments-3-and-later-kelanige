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
#include "aesd_ioctl.h"

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
    struct aesd_dev* dev = (struct aesd_dev*)filp->private_data;
    ssize_t retval = 0;
    size_t offset = 0;
    size_t remaining_bytes = 0;
    struct aesd_buffer_entry* entry = NULL;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    if (mutex_lock_interruptible(&dev->buffer_mutex)) {
        mutex_unlock(&dev->buffer_mutex);
        return -ERESTARTSYS;
    }
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &offset);
    if (entry == NULL) {
        mutex_unlock(&dev->buffer_mutex);
        return 0;
    }
    remaining_bytes = copy_to_user(buf, entry->buffptr + offset, entry->size - offset);
    retval = entry->size - remaining_bytes - offset;
    mutex_unlock(&dev->buffer_mutex);
    if (remaining_bytes > 0) {
        return -EFAULT;
    }
    *f_pos += retval;
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev* dev = (struct aesd_dev*)filp->private_data;
    ssize_t retval = -ENOMEM;
    char* user_buf = NULL;
    int has_newline = 0;
    size_t offset;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    // Copy user buffer to kernel memory.
    user_buf = kmalloc(count, GFP_KERNEL);
    if (copy_from_user(user_buf, buf, count)) {
        kfree(user_buf);
        return -EFAULT;
    }
    if (mutex_lock_interruptible(&dev->buffer_mutex)) {
        kfree(user_buf);
        mutex_unlock(&dev->buffer_mutex);
        return -ERESTARTSYS;
    }

    for (offset = 0; offset < count; ++offset) {
        if (*(user_buf + offset) == '\n') {
            has_newline = 1;
            break;
        }
    }
    if (dev->string == NULL) {
        dev->string = kmalloc(BUFFER_SIZE, GFP_KERNEL);
        memset(dev->string, 0, BUFFER_SIZE);
        dev->string_size = 0;
        dev->string_capacity = BUFFER_SIZE;
    }
    if (dev->string_size + count > dev->string_capacity) {
        const size_t new_size = 2 * dev->string_capacity;
        dev->string = krealloc(dev->string, new_size, GFP_KERNEL);
        dev->string_capacity = new_size;
    }
    memcpy(&dev->string[dev->string_size], user_buf, count);
    dev->string_size += count;

    if (has_newline == 1) {
        struct aesd_buffer_entry entry;
        entry.buffptr = dev->string;
        entry.size = dev->string_size;

        dev->string = NULL;
        dev->string_size = 0;
        dev->string_capacity = 0;
        *f_pos += entry.size;
        if (dev->buffer.full) {
            size_t offset;
            struct aesd_buffer_entry* entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, 0, &offset);
            kfree(entry->buffptr);
        }
        aesd_circular_buffer_add_entry(&dev->buffer, entry);
    }
    mutex_unlock(&dev->buffer_mutex);
    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence) {
    struct aesd_dev* dev = (struct aesd_dev*)filp->private_data;
    loff_t retval = 0;
    size_t total_size = 0;
    size_t index = 0;
    struct aesd_buffer_entry* entry;
    PDEBUG("llseek %lld bytes, whence: %d", offset, whence);
    if (mutex_lock_interruptible(&dev->buffer_mutex)) {
        mutex_unlock(&dev->buffer_mutex);
        return -ERESTARTSYS;
    }
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &dev->buffer, index) {
        total_size += entry->size;
    }
    retval = fixed_size_llseek(filp, offset, whence, total_size);
    mutex_unlock(&dev->buffer_mutex);
    return retval;
}

long aesd_adjust_file_offset(struct file *filp, uint32_t cmd, uint32_t offset) {
    struct aesd_dev* dev = (struct aesd_dev*)filp->private_data;
    struct aesd_buffer_entry* entry;
    size_t index;
    long pos = 0;

    if (mutex_lock_interruptible(&dev->buffer_mutex)) {
        mutex_unlock(&dev->buffer_mutex);
        return -ERESTARTSYS;
    }
    if (cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
        mutex_unlock(&dev->buffer_mutex);
        return -EINVAL;
    }
    entry = &dev->buffer.entry[(dev->buffer.out_offs + cmd) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED];
    if (offset >= entry->size) {
        mutex_unlock(&dev->buffer_mutex);
        return -EINVAL;
    }
    pos += offset;
    for (index = 0; index < cmd; ++index) {
        entry = &dev->buffer.entry[(dev->buffer.out_offs + index) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED];
        pos += entry->size;
    }
    mutex_unlock(&dev->buffer_mutex);
    aesd_llseek(filp, pos, SEEK_CUR);
    return 0;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    long retval = 0;
    PDEBUG("ioctl %u", cmd);

    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
    if (_IOC_NR(cmd) != AESDCHAR_IOC_MAXNR) return -ENOTTY;

    switch (cmd) {
        case AESDCHAR_IOCSEEKTO: {
            struct aesd_seekto seekto;
            if ( copy_from_user(&seekto, (const void __user *)arg, sizeof(struct aesd_seekto)) != 0) {
                return -EFAULT;
            } else {
                retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
            }
            break;
        }
    }
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
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

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
