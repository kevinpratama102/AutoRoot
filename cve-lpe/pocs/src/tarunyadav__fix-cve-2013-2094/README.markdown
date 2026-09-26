# CVE-2013-2094 Mitigation Fix #

This script provides an easy mechnism for generating portable
SystemTap modules that can be loaded with systemtap-runtime to
mitigate the vulnerability described in CVE-2013-2094.

This toolset is aimed towards RHEL6, but will likely work without
modification on other Enterprise Linux based distros.

# Instructions #

Ensure you have the debuginfo repository for your distro installed.

Run the build for the kernel version you wish to target

<pre><code>./build.sh $(uname -r)
</code></pre>

You'll be provided with a kernel module that looks something like:

<pre><code>cve_2013_2094__2_6_32_358_6_1_el6_x86_64.ko
</code></pre>

To put this into affect, you must distribute the module to the target
systems, and run the following command:

<pre><code>staprun -L cve_2013_2094__2_6_32_358_6_1_el6_x86_64.ko
</code></pre>

IMPORTANT NOTE: You must reload this module after every restart.
