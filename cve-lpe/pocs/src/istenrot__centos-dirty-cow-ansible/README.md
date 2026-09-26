# Ansible CVE-2016-5195 mitigation playbook
Ansible playbook to mitigate CVE-2016-5195 on CentOS/Scientific Linux with SystemTap.

Automating this mitigation recipe found on Red Hat Bugzilla:
[https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c13](https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c13)

This playbook install Kernel debuginfo packages and SystemTap. Then it will generate a SystemTap module and runs it in the background. If you reboot the server you'll need to re-run this playbook to restore the mitigation.

## Disclaimer

I'm not a kernel security expert, nor a SystemTap expert. I've not verified effectiveness of this vulnerability mitigation recipe. I give no guarantees of any kind. This playbook may break your server and cause data loss for you.

## Author

Ilari Stenroth

Twitter: @istenrot

