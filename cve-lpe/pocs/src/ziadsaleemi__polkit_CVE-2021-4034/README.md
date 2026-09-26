Role Name
=========

Ansible role to patch  RHSB-2022-001 Polkit Privilege Escalation - (CVE-2021-4034)

Requirements
------------
Repositories should be configured.

Role Variables
--------------

All the variables are in /vars/main.yml file. A list of polkit vulnerable packages is also added to the file as a list, you can update the list depending on your use case. You can also add the flavors of linux and their releases. 

Dependencies
------------

Please make sure the repositories are already configured!!!


Example Playbook
----------------

Download repo in your roles directory:
```
    - hosts: all
      roles:
         - polkit_CVE-2021-4034
```
If you are downloading and using outside your roles directory use absolute path or relative path to execute role:
```
    - hosts: all
      roles:
        - /home/user/some-direcotory/polkit_CVE-2021-4034
```

Structure
------------

```
polkit_CVE-2021-4034/
├── defaults
│   └── main.yml
├── files
├── handlers
│   └── main.yml
├── meta
│   └── main.yml
├── README.md
├── tasks
│   ├── main.yml
│   └── patch.yml
├── templates
├── tests
│   ├── inventory
│   └── test.yml
└── vars
    └── main.yml
```
License
-------

GNU Public License v3.0

Author Information
------------------

Ziad Saleemi