# Autopwn PLAN — astinapura (linux)
- Dibuat: 20260928-190606
- Dataset: 2026-09-26T21:01:53Z (23847 CVE)
- CVE terseleksi (has_poc, bukan possible): 14

> Otomasi: checker-first; BP = checker-stage saja (bila --allow-backported);
> berhenti di root pertama; exploit kernel bisa crash box lab — sadar risiko.

## CVE-2026-31431 — HIGH 7.8 **[KEV]**
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>=6.13 <6.18.22]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  crypto: algif_aead - Revert to operating out-of-place  This mostly reverts commit 72548b093ee3 except for the copying of the associated data.  There is no benefit in operating in-place in algif_aead since the source and destination
- repo: https://github.com/John-Popovici/CVE-2026-31431-CopyFail-Linux-PrivEsc, https://github.com/theori-io/copy-fail-CVE-2026-31431, https://github.com/Alfredooe/CVE-2026-31431, https://github.com/painoob/Copy-Fail-Exploit-CVE-2026-31431, https://github.com/badsectorlabs/copyfail-go, https://github.com/tgies/copy-fail-c, https://github.com/ZephrFish/CopyFail-CVE-2026-31431, https://github.com/Crihexe/co
- checker lokal: CVE-2026-31431-prebuilt-verify_vulneurable | exploit lokal: CVE-2026-31431-prebuilt-exploit

## CVE-2026-43284 — HIGH 8.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>=6.13 <6.18.28]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  xfrm: esp: avoid in-place decrypt on shared skb frags  MSG_SPLICE_PAGES can attach pages from a pipe directly to an skb. TCP marks such skbs with SKBFL_SHARED_FRAG after skb_splice_from_iter(), so later paths that may modify packet
- repo: https://github.com/Percivalll/Dirty-Frag-Kubernetes-PoC, https://github.com/scriptzteam/Paranoid-Dirty-Frag-CVE-2026-43284, https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4, https://github.com/0xBlackash/CVE-2026-43284, https://github.com/suominen/CVE-2026-43284, https://github.com/AK777177/Dirty-Frag-Analysis, https://github.com/haydenjames/dirty-frag-check, https://github.com/m
- checker lokal: - | exploit lokal: CVE-2026-43284-prebuilt-dirtyfrag

## CVE-2026-43503 — HIGH 8.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>=6.13 <6.18.33]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  net: skbuff: propagate shared-frag marker through frag-transfer helpers  Two frag-transfer helpers (__pskb_copy_fclone() and skb_shift()) fail to propagate the SKBFL_SHARED_FRAG bit in skb_shinfo()->flags when moving frags from sou
- repo: https://github.com/0xBlackash/CVE-2026-43503, https://github.com/mooder1/dirtyclone-CVE-2026-43503, https://github.com/sec0x/CVE-2026-43503, https://github.com/douglasmun/pagecache-lpe-containment-kit, https://github.com/gl1tch0x1/DirtyClone, https://github.com/entra1337/DirtyClone, https://github.com/SecureWithUmer/CVE-2026-43503, https://github.com/lieehrdiansyah12/CVE-2026-43503
- checker lokal: - | exploit lokal: CVE-2026-43503-prebuilt-DirtyClone

## CVE-2026-53075 — HIGH 8.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>=6.13 <6.18.33]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  ppp: require CAP_NET_ADMIN in target netns for unattached ioctls  /dev/ppp open is currently authorized against file->f_cred->user_ns, while unattached administrative ioctls operate on current->nsproxy->net_ns.  As a result, a loca
- repo: https://github.com/foxirain/linux-kernel-codex-harness-v2, https://github.com/lottiedeyan/CVE-2026-53075poc
- checker lokal: - | exploit lokal: -

## CVE-2020-27815 — HIGH 7.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>4.4.249]` vs terpasang `6.14.0-35-generic`
- A flaw was found in the JFS filesystem code in the Linux Kernel which allows a local attacker with the ability to set extended attributes to panic the system, causing memory corruption or escalating privileges. The highest threat from this vulnerability is to confidentiality, integrity, as well as s
- repo: https://github.com/Trinadh465/linux-4.19.72_CVE-2020-27815
- checker lokal: - | exploit lokal: -

## CVE-2026-23111 — HIGH 7.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>=6.13 <6.18.10]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  netfilter: nf_tables: fix inverted genmask check in nft_map_catchall_activate()  nft_map_catchall_activate() has an inverted element activity check compared to its non-catchall counterpart nft_mapelem_activate() and compared to wha
- repo: https://github.com/HORKimhab/CVE-2026-23111, https://github.com/criann/check-cve-2026-23111, https://github.com/0xBlackash/CVE-2026-23111, https://github.com/seguridadentrerios/CVE-2026-23111, https://github.com/ishankaru/CVE-2026-23111-nftables-lab, https://github.com/Baba01hacker666/CVE-2026-23111, https://github.com/bakano98/cve-2026-23111-poc, https://github.com/vrtlbob/Linux-Kernel-Vulnerabil
- checker lokal: - | exploit lokal: CVE-2026-23111-prebuilt-exp

## CVE-2026-43500 — HIGH 7.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>5.3 <6.18.29]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  rxrpc: Also unshare DATA/RESPONSE packets when paged frags are present  The DATA-packet handler in rxrpc_input_call_event() and the RESPONSE handler in rxrpc_verify_response() copy the skb to a linear one before calling into the se
- repo: https://github.com/attaattaatta/CVE-2026-43500, https://github.com/vorkampfer/dirty_frag_mitigation
- checker lokal: - | exploit lokal: -

## CVE-2026-46300 — HIGH 7.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>=6.13 <6.18.33]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  net: skbuff: preserve shared-frag marker during coalescing  skb_try_coalesce() can attach paged frags from @from to @to.  If @from has SKBFL_SHARED_FRAG set, the resulting @to skb can contain the same externally-owned or page-cache
- repo: https://github.com/HORKimhab/CVE-2026-46300, https://github.com/Sentebale/CVE-2026-46300, https://github.com/0xBlackash/CVE-2026-46300, https://github.com/ExploitEoom/CVE-2026-46300, https://github.com/First-John/cve_2026_frag_family_fix, https://github.com/Maxime288/Fragnesia-CVE-2026-46300, https://github.com/nonameuserosint-hue/Fragnesia-go, https://github.com/AzDevops143/FRAGNESIA-Charan-cve-2
- checker lokal: - | exploit lokal: CVE-2026-46300-prebuilt-exploit

## CVE-2026-46331 — HIGH 7.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>=6.13 <6.18.36]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  net/sched: fix pedit partial COW leading to page cache corruption  tcf_pedit_act() computes the COW range for skb_ensure_writable() once before the key loop using tcfp_off_max_hint, but the hint does not account for the runtime hea
- repo: https://github.com/sgkdev/packet_edit_meme, https://github.com/0xBlackash/CVE-2026-46331, https://github.com/HORKimhab/CVE-2026-46331, https://github.com/vulnquest58/dirtyclone-exploit, https://github.com/Quaerendir/cve-2026-46331-audit, https://github.com/seguridadentrerios/CVE-2026-46331, https://github.com/g0thamRabb1t/CVE-2026-46331-pedit-COW-detection, https://github.com/V0IDNETWORK/CVE-2026-
- checker lokal: - | exploit lokal: CVE-2026-46331-prebuilt-exp

## CVE-2026-52943 — HIGH 7.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>=6.13 <6.18.35]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  net: skbuff: fix missing zerocopy reference in pskb_carve helpers  pskb_carve_inside_header() and pskb_carve_inside_nonlinear() both copy the old skb_shared_info header into a new buffer via memcpy(), which includes the destructor_
- repo: https://github.com/vn-lazyming/CVE-2026-52943
- checker lokal: - | exploit lokal: -

## CVE-2026-64600 — HIGH 7.8
- matched_by: kernel (high)
- constraint: `linux:linux_kernel [>=6.13 <6.18.39]` vs terpasang `6.14.0-35-generic`
- In the Linux kernel, the following vulnerability has been resolved:  xfs: resample the data fork mapping after cycling ILOCK  xfs_reflink_fill_{cow_hole,delalloc} are both presented with an inode, a data fork mapping, and a cow fork mapping.  Unfortunately, these two helpers cycle the ILOCK to grab 
- repo: https://github.com/0xBlackash/CVE-2026-64600, https://github.com/HORKimhab/CVE-2026-64600, https://github.com/vulnquest58/VQ-RefluxCore, https://github.com/Debajyoti0-0/CVE-2026-64600, https://github.com/litosmartin/CVE-2026-64600-Refluxfs-PoC, https://github.com/bha-vin/CVE-2026-64600-Exploit, https://github.com/letsr00t/RefluxFS_CVE-2026-64600, https://github.com/masrikky/CVE-2026-64600-RefluXFS
- checker lokal: - | exploit lokal: CVE-2026-64600-prebuilt-refluxfs

## CVE-2026-24072 — HIGH 8.8
- matched_by: package (high)
- constraint: `apache:http_server [<2.4.67]` vs terpasang `apache2 2.4.58-1ubuntu8.8`
- An escalation of privilege bug in various modules in Apache HTTP 2.4.66 and earlier allows local .htaccess authors to read files with the privileges of the httpd user.  Users are recommended to upgrade to version 2.4.67, which fixes this issue.
- repo: https://github.com/meh098/CVE-2026-24072-Analysis
- checker lokal: - | exploit lokal: -

## CVE-2022-26488 — HIGH 7.0
- matched_by: package (high)
- constraint: `python:python [<=3.7.12]` vs terpasang `python-apt-common 2.7.7ubuntu5`
- constraint: `python:python [<=3.7.12]` vs terpasang `python-babel-localedata 2.10.3-3build1`
- In Python before 3.10.3 on Windows, local users can gain privileges because the search path is inadequately secured. The installer may allow a local attacker to add user-writable directories to the system search path. To exploit, an administrator must have installed Python for all users and enabled 
- repo: https://github.com/techspence/PyPATHPwner
- checker lokal: - | exploit lokal: -

## CVE-2018-1000117 — MEDIUM 6.7
- matched_by: package (high)
- constraint: `python:python [>=3.6.0 <3.6.5]` vs terpasang `python3-idna 3.6-2ubuntu0.1`
- constraint: `python:python [>=3.2.0 <3.4.9]` vs terpasang `python3-oauthlib 3.2.2-1`
- Python Software Foundation CPython version From 3.2 until 3.6.4 on Windows contains a Buffer Overflow vulnerability in os.symlink() function on Windows that can result in Arbitrary code execution, likely escalation of privilege. This attack appears to be exploitable via a python script that creates 
- repo: https://github.com/u0pattern/CVE-2018-1000117-Exploit
- checker lokal: - | exploit lokal: -
