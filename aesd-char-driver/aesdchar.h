/*
 * aesdchar.h
 *
 *  Created on: Oct 23, 2019
 *      Author: Dan Walkes
 */

#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#define AESD_DEBUG 1  //Remove comment on this line to enable debug
#define AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED 10

#undef PDEBUG             /* undef it, just in case */
#ifdef AESD_DEBUG
#  ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "aesdchar: " fmt, ## args)
#  else
     /* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#include "aesd-circular-buffer.h"

struct aesd_dev
{
    /**
     * TODO: Add structure(s) and locks needed to complete assignment requirements
     */
    char* buffers[AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED];
    size_t write_position;
    size_t read_position;

    struct mutex circular_buffer_lock;
    struct aesd_circular_buffer circular_buffer;
    struct cdev cdev;     /* Char device structure      */
};


#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */
