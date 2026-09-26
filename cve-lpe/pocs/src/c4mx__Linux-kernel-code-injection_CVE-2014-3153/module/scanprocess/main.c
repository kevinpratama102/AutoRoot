/*  
 *  hello-1.c - The simplest kernel module.
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/sched.h>    /* Needed for current */
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/path.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/page-flags.h>
#include "lime.h"

bool comparename(struct file *,char *);

// For writting the dump
char * path = 0;
int dio = 0;
int write_vaddr_disk(void * , size_t);
int setup_disk(unsigned long);
void cleanup_disk(void);
char * name = 0;
char * mapped_file = 0;

module_param(name, charp, S_IRUGO);
module_param(mapped_file, charp, S_IRUGO);
module_param(path, charp, S_IRUGO);



int init_module(void) {
    struct task_struct * task, * begin;
    bool found;
    struct mm_struct * mm;
    struct vm_area_struct * vmas;
    //char * buf;
    struct file * f;
    //pgd_t * save;
    //unsigned long s;
    unsigned long address;
    pgd_t * pgd;
    pmd_t * pmd;
    pte_t * pte;
    struct page * page = NULL;
    pud_t * pud;
    int offset;
    void * kernel_address;
    int cpt = 0;
    int cpt_vmas = 0;

    if (!name) {
        printk("No process name given! add: name=toto");
        return -EINVAL;
    }
    if (!mapped_file) {
        printk("No mapped file name given! add: mapped_file=/media/sf_module/toto");
        return -EINVAL;
    }
    if (!path) {
        printk("No output file given! add: path=/data/dump.bin");
        return -EINVAL;
    }

    found = false;
    printk(KERN_INFO "********************************\n");
    printk(KERN_INFO "Scanprocess:\n");
    printk(KERN_INFO "Searches the %s process.\n", name);
    printk(KERN_INFO "********************************\n");

    task = current;
    begin = current;
    printk("[*] Current task: %s\n", current->comm);

    do {
        printk("%s\n", task->comm);
        //if (strncmp(task->comm, name+strlen(name)-15, 16) == 0)
        if (strncmp(task->comm, name, 16) == 0) {
            printk("[*] Process %s found !\n", name);
            found = true;
            break;
        }
        task = next_task(task);
    } while (task != begin);


    //init = task;

    if (found) {
        mm = task->mm;
        vmas = mm->mmap;
        do {
            f = vmas->vm_file;
            if (f != NULL) {
                /*
                buf = kmalloc(sizeof(char) * 256, GFP_KERNEL);
                dentry_path_raw(f->f_path.dentry, buf, 256);
                buf[255] = '\0';
                printk("buf: %s\n", buf);
                kfree(buf);
                */
                //if (comparename(f, mapped_file) && vmas->vm_flags & VM_WRITE) {
                if (vmas->vm_flags & VM_WRITE) {
                    cpt_vmas++;
                    printk("Memory mapping of toto code found (%i).\n", cpt_vmas);
                    //save = current->mm->pgd;


                    printk("\nCode  Segment start = 0x%lx, end = 0x%lx \n"
                        "Data  Segment start = 0x%lx, end = 0x%lx\n"
                        "Stack Segment start = 0x%lx\n",
                        mm->start_code, mm->end_code,
                        mm->start_data, mm->end_data,
                        mm->start_stack);

                    // Switching of context
                    //current->mm->pgd = mm->pgd;
                    //printk("HACK current->mm->pgd = mm->pgd;\n");
                    printk("Writting a dump of the process in %s\n", path);
                    //i = min((size_t) PAGE_SIZE, s);

                    address = vmas->vm_start;
                    setup_disk(address);
                    printk("Starting writting from address: %lx\n", address);
                    //printk("start + PAGE_SIZE: %lx\n", address+PAGE_SIZE/DIVPAGE);
                    printk("End at address: %lx\n", vmas->vm_end);
                    while (address < vmas->vm_end) {
                        pgd = pgd_offset(mm, address);
                        pud = pud_offset(pgd, address);
                        pmd = pmd_offset(pud, address);
                        pte = pte_offset_map(pmd, address);
                        page = pte_page( * pte);

                        //if (page->flags && PG_active != 0)
                        {
                            // Writting page
                            if (address + PAGE_SIZE > vmas->vm_end)
                                offset = vmas->vm_end - address;
                            else
                                offset = PAGE_SIZE;
                            //printk("Writting %i bytes: ", offset);

                            // Mapping a page into the kernel space
                            kernel_address = kmap(page);

                            // Writting
                            //s = write_vaddr_disk(kernel_address, offset);
                            write_vaddr_disk(kernel_address, offset);
                            cpt = cpt + 1;
                            // unmapping from kernel memory
                            kunmap(page);
                            //printk("written: %lu\n", s); 
                        }
                        address += PAGE_SIZE;
                        //printk("Dumping address: %lx\n", address);
                    }
                    cleanup_disk();

                    //current->mm->pgd = save;
                    printk("Start at address: %lx\n", vmas->vm_start);
                    printk("End at address: %lx\n", vmas->vm_end);

                }
            }

            vmas = vmas->vm_next;
        } while (vmas != NULL);
        printk("END. All is good !\n");
        printk("cpt: %i\n", cpt);
        printk("cpt_vmas: %i\n", cpt_vmas);
        printk("PAGE SIZE: %li\n", PAGE_SIZE);
    } else {
        printk("Process %s not found !\n", name);
    }


    /* 
     * A non 0 return means init_module failed; module can't be loaded. 
     */
    return 0;
}

bool comparename(struct file * file, char * name) {
    char * tmp;
    char * pathname;
    struct path * path;
    int res;
    res = false;

    path = & file->f_path;
    path_get(path);
    //spin_unlock(files->file_lock);

    tmp = (char * ) __get_free_page(GFP_TEMPORARY);

    if (!tmp) {
        path_put(path);
        return false;
    }

    pathname = d_path(path, tmp, PAGE_SIZE);
    path_put(path);

    if (IS_ERR(pathname)) {
        return false;
    }

    //printk("path: %s\n", pathname);
    if (strcmp(pathname, name) == 0) {
        //printk("found !: %s\n", pathname);
        res = true;
    }
    /* do something here with pathname */

    free_page((unsigned long) tmp);

    return res;

}

void cleanup_module(void) {
    printk(KERN_INFO "Exiting module scanprocess.\n");
}


MODULE_LICENSE("GPL");