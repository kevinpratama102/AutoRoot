#!/bin/env sh
# fix-cve-2013-2094/build.sh
#
# Assists in downloading the appropriate kernels and debuginfo packages,
# for a provided kernel version (uname -r), and compiling a systemtap script
# into a kernel module that mitigates CVE-2013-2094.
#
# note: requires debuginfo repository
#
# Author: Aaron Russo <arusso@berkeley.edu>
#   Date: 15-May-2013
#
VER=$1

if [[ "$VER" == "" ]]; then
  VER=$(uname -r)
fi

yum remove -y kernel-debuginfo-common-x86_64
yum install -y --enablerepo=*debuginfo kernel-$VER kernel-debuginfo-common-x86_64-$VER kernel-devel-$VER kernel-debuginfo-$VER systemtap systemtap-runtime 2>/dev/null

[ "$?" != "0" ] && ( echo error installing packages for kernel version $VER )

FILE_VER=$(echo $VER | sed 's/[\.-]/_/g')

stap -g -r $VER fix-cve-2013-2094.stp -m "cve_2013_2094__${FILE_VER}" -p4
