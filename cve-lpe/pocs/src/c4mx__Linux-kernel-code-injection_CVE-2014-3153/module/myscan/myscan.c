#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>   /* Needed for KERN_INFO */
#include <linux/sched.h>    /* Needed for current */


// For writting the dump
// char * path = 0;
// char *name = 0;
// char * mapped_file = 0;

// module_param(name, charp, S_IRUGO);
// module_param(mapped_file, charp, S_IRUGO);
// module_param(path, charp, S_IRUGO);

int init_module(void) {
    struct task_struct *start, *task;
  
    start = next_task(current);
    task = start;

    printk("[*] current task name: %s\n", current->comm);

    do {
        printk("%s\n", task->comm);
        task = next_task(task);
    } while (task != start);

    return 0;
}


void cleanup_module(void) {
    printk(KERN_INFO "[*] Exiting module scanprocess.\n");
}


MODULE_LICENSE("GPL");
