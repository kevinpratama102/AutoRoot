/*  
 *  current.c - Show how kernel know current task address
 */
#include <linux/module.h>   /* Needed by all modules */
#include <linux/kernel.h>   /* Needed for KERN_INFO */
#include <linux/sched.h>    /* Needed for current */

int init_module(void)
{   
    printk("[*] current task name: %s\n", current->comm);
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "[*] Goodbye world!\n");
}

MODULE_LICENSE("GPL");