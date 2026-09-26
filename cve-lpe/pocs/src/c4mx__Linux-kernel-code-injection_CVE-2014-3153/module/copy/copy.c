/*  
 *  copy.c - Show how kernel copy a buffer from userland.
 */
#include <linux/module.h>   /* Needed by all modules */
#include <linux/kernel.h>   /* Needed for KERN_INFO */
//#include <linux/sched.h>    /* Needed for current */

int init_module(void)
{   
    unsigned long buf;
    
    if (copy_from_user(&buf, src, len))
        return -EFAULT;

    /* 
     * A non 0 return means init_module failed; module can't be loaded. 
     */
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "[*] Goodbye world!\n");
}