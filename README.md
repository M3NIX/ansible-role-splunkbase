# ansible-role-splunkbase

This ansible role will download and install an app from https://splunkbase.splunk.com into `/opt/splunk/etc/apps/`.
For more details on how to use the module have a look [here](https://github.com/M3NIX/ansible-module-splunkbase.git).

## Getting Started

Copy this repo into your roles path:
```
git clone --recurse-submodules https://github.com/M3NIX/ansible-role-splunkbase.git splunkbase
```

Use the role in a playbook e.g.:
```yaml
---
- hosts: all
  roles:
    - splunkbase
  vars:
    splunkbase_user: my_username
    splunkbase_password: changeme
    splunkbase_apps:
      - https://splunkbase.splunk.com/app/742/  # Add-on for Microsoft Windows
      - https://splunkbase.splunk.com/app/833/  # Add-on for Unix and Linux
      - https://splunkbase.splunk.com/app/5709/ # Add-on for Sysmon
```

## Requirements

- python > 3.6
- python-request lib must be installed on target host
- the target host needs access to https://splunkbase.splunk.com
- user account for splunkbase
