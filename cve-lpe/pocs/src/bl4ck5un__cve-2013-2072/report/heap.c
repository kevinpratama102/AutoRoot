 219 static PyObject *pyxc_vcpu_setaffinity(XcObject *self,
 220                                        PyObject *args,
 221                                        PyObject *kwds)
 222 {
 223     uint32_t dom;
 224     int vcpu = 0, i;
 225     xc_cpumap_t cpumap; /* (1) */
 226     PyObject *cpulist = NULL;
 227     int nr_cpus;
 228 
 229     static char *kwd_list[] = { "domid", "vcpu", "cpumap", NULL };

 235    /* nr_cpus = xc_get_max_cpus(self->xc_handle);
 236     if ( nr_cpus < 0 )
 237         return pyxc_error_to_exception(self->xc_handle);
 238 	*/
 239     cpumap = xc_cpumap_alloc(self->xc_handle); /* (2) */
	 //...
 243     if ( (cpulist != NULL) && PyList_Check(cpulist) )
 244     {
 245         for ( i = 0; i < PyList_Size(cpulist); i++ )
 246         {
 247             long cpu = PyInt_AsLong(PyList_GetItem(cpulist, i));
 248             /*if ( cpu < 0 || cpu >= nr_cpus )
 249             {
 250                 free(cpumap);
 251                 errno = EINVAL;
 252                 PyErr_SetFromErrno(xc_error_obj);
 253                 return NULL;
 254             }*/
 255             cpumap[cpu / 8] |= 1 << (cpu % 8);  /* (3) */
		 /* full ability to change every bit */
 256         }
 257     }
 258 
 259     if ( xc_vcpu_setaffinity(self->xc_handle, dom, vcpu, cpumap) != 0 )
 260     {
 261         free(cpumap);  /* (4'1) */
 262         return pyxc_error_to_exception(self->xc_handle);
 263     }
 264     Py_INCREF(zero);
 265     free(cpumap);  /* (4'2) */
 266     return zero;
 267 }

//==========
 354 typedef uint8_t *xc_cpumap_t;


//==========
 192 int xc_vcpu_setaffinity(xc_interface *xch,
 193                         uint32_t domid,
 194                         int vcpu,
 195                         xc_cpumap_t cpumap)
 196 {
 197     DECLARE_DOMCTL;
 198     DECLARE_HYPERCALL_BUFFER(uint8_t, local);
 199     int ret = -1;
 200     int cpusize;
 201 
 202     cpusize = xc_get_cpumap_size(xch);
 203     if (!cpusize)
 204     {
 205         PERROR("Could not get number of cpus");
 206         goto out;
 207     }
 208 
 209     local = xc_hypercall_buffer_alloc(xch, local, cpusize);
 210     if ( local == NULL )
 211     {
 212         PERROR("Could not allocate memory for setvcpuaffinity domctl hypercall");
 213         goto out;
 214     }
 215 
 216     domctl.cmd = XEN_DOMCTL_setvcpuaffinity;
 217     domctl.domain = (domid_t)domid;
 218     domctl.u.vcpuaffinity.vcpu    = vcpu;
 219 
 220     memcpy(local, cpumap, cpusize); /* (4) */
 221 
 222     set_xen_guest_handle(domctl.u.vcpuaffinity.cpumap.bitmap, local);
 223 
 224     domctl.u.vcpuaffinity.cpumap.nr_bits = cpusize * 8;
 225 
 226     ret = do_domctl(xch, &domctl);
 227 
 228     xc_hypercall_buffer_free(xch, local);
 229 
 230  out:
 231     return ret;
 232 }


//===========
 86 xc_cpumap_t xc_cpumap_alloc(xc_interface *xch)
 87 {
 88     int sz;
 89 
 90     sz = xc_get_cpumap_size(xch);
 91     if (sz == 0)
 92         return NULL;
 93     return calloc(1, sz);
 94 }


 68 int xc_get_cpumap_size(xc_interface *xch)
 69 {
 70     int max_cpus = xc_get_max_cpus(xch);
 71
 72     if ( max_cpus < 0 )
 73         return -1;
 74     return (max_cpus + 7) / 8;
 75 }


/*
The calloc() function allocates memory for an array of nmemb elements of size bytes each and returns a pointer to the allocated memory. The memory is set to zero. If nmemb or size is 0, then calloc() returns either NULL, or a unique pointer value that can later be successfully passed to free().
*/

//=========
1121 struct malloc_chunk {
1122 
1123   INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
1124   INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */
1125 
1126   struct malloc_chunk* fd;         /* double links -- used only if free. */
1127   struct malloc_chunk* bk;
1128 
1129   /* Only used for large blocks: pointer to next larger size.  */
1130   struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
1131   struct malloc_chunk* bk_nextsize;
1132 };



//======backward exploit free=====
3891     /* consolidate backward */
3892     if (!prev_inuse(p)) {
3893       prevsize = p->prev_size;  /* (1) */
3894       size += prevsize;
3895       p = chunk_at_offset(p, -((long) prevsize));  /* (2) */
3896       unlink(p, bck, fwd);
3897     }

1280 #define PREV_INUSE 0x1
1283 #define prev_inuse(p)       ((p)->size & PREV_INUSE)
1323 #define chunk_at_offset(p, s)  ((mchunkptr)(((char*)(p)) + (s)))

1423 /* Take a chunk off a bin list */
/* In control: p, p->fd(A), p->bk(B);*/
1424 #define unlink(P, BK, FD) {                                          
1425   FD = P->fd;   \    // FD = A
1426   BK = P->bk;   \    // BK = B
1430   FD->bk = BK;  \    // *(A+12) = B;
1431   BK->fd = FD;  \    // *(B+8) = A;
1451 }

/*
1) overwrite p->prev_size to get p pointed to fake header;
2) where *(p+8)=A; *(p+12)=B;
*/


//========forward exploit free=====
3856	   nextchunk = chunk_at_offset(p, size);
3901       nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
4084       if (!nextinuse) {
4085         unlink(nextchunk, bck, fwd);
4086         size += nextsize;
4087       } else
4088         clear_inuse_bit_at_offset(nextchunk, 0);

1280 #define PREV_INUSE 0x1
1287 #define IS_MMAPPED 0x2
1296 #define NON_MAIN_ARENA 0x4
1313 #define chunksize(p)  ((p)->size & ~(SIZE_BITS))
1310 #define SIZE_BITS (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA) // 0x07
1437 #define next_chunk(p) ((mchunkptr)( ((char*)(p)) + ((p)->size & ~SIZE_BITS) ))
1458 #define inuse_bit_at_offset(p, s) (((mchunkptr)(((char*)(p)) + (s)))->size & PREV_INUSE)


1986 /*
1987   Properties of inuse chunks
1988 */
1989
1990 static void do_check_inuse_chunk(mstate av, mchunkptr p)
1991 {
1992   mchunkptr next;
1993
1994   do_check_chunk(av, p);
1995
1996   if (chunk_is_mmapped(p))
1997     return; /* mmapped chunks have no next/prev */
1998
1999   /* Check whether it claims to be in use ... */
2000   assert(inuse(p));
2001
2002   next = next_chunk(p);
2003
2004   /* ... and is surrounded by OK chunks.
2005     Since more things can be checked with free chunks than inuse ones,
2006     if an inuse chunk borders them and debug is on, it's worth doing them.
2007   */
2008   if (!prev_inuse(p))  {
2009     /* Note that we cannot even look at prev unless it is not inuse */
2010     mchunkptr prv = prev_chunk(p);
2011     assert(next_chunk(prv) == p);
2012     do_check_free_chunk(av, prv);
2013   }
2014
2015   if (next == av->top) {
2016     assert(prev_inuse(next));
2017     assert(chunksize(next) >= MINSIZE);
2018   }
2019   else if (!inuse(next))
2020     do_check_free_chunk(av, next);
2021 }
