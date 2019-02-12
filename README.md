# Ansible Syspass Lookup (ansible-syspass-lookup)
Ansible lookup plugin to create an get password from syspass Systems Password Manager vault (https://github.com/nuxsmin/sysPass)
and Syspass Python class.

## Getting Started
These instructions will get you simple test to manage passwords with Ansible and store it to Syspass > 3

### Prerequisites

You need a Ansible environnement work for minimum one host and an Syspass installation v3.0+ .

### Installing

* On your Ansible configuration, put syspass.py in your directory of lookup plugins declared in ansible.cfg by `lookup_plugins`

Exemple of local ansible.cfg

```
lookup_plugins = ./plugins/lookup
```

* Put syspass.py in `plugins/lookup`.

* Edit exemple/test/ansible-playbook-test.yml and set the hostname of the host you will test, Syspass URL, API Key and Token Password you have created in Syspass backoffice

* Launch Ansible like this

```
ansible-playbook exemple/test/ansible-playbook-test.yml
```

The result look like this :

```
PLAY [hostname] **********************************************************************************************************************************************

TASK [SysPass | Minimal test | get and if not exist insert] ************************************************************************************************************************
changed: [hostname] =>
  msg: Q9A-Kb-3XL[o.uhX=t/f])?qC{l+actZ=cUqqQ9q

TASK [SysPass | Minimal test | get and compare] ************************************************************************************************************************************
changed: [hostname] =>
  msg: Q9A-Kb-3XL[o.uhX=t/f])?qC{l+actZ=cUqqQ9q

TASK [SysPass | Minimal test | delete account] *************************************************************************************************************************************
changed: [hostname] =>
  msg: Deleted Account

TASK [SysPass | Complete test | get and if not exist insert] ***********************************************************************************************************************
changed: [hostname] =>
  msg: 9o9zEfYnqMTKfYn3tl5q

TASK [SysPass | Complete test | get and compare] ***********************************************************************************************************************************
changed: [hostname] =>
  msg: 9o9zEfYnqMTKfYn3tl5q

TASK [SysPass | Complete test | delete account] ************************************************************************************************************************************
changed: [hostname] =>
  msg: Deleted Account

PLAY RECAP *************************************************************************************************************************************************************************
hostname : ok=7    changed=6    unreachable=0    failed=0
```
