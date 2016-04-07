# Ansible Role: Let's Encrypt

[![Build Status](https://travis-ci.org/geerlingguy/ansible-role-letsencrypt.svg?branch=master)](https://travis-ci.org/geerlingguy/ansible-role-letsencrypt)

Installs Let's Encrypt for RHEL/CentOS or Debian/Ubuntu.

## Requirements

Let's Encrypt requires `git` to be installed. You can install using the `geerlingguy.git` role.

## Role Variables

None.

## Dependencies

None.

## Example Playbook

    - hosts: servers
      roles:
        - geerlingguy.letsencrypt

## License

MIT / BSD

## Author Information

This role was created in 2016 by [Jeff Geerling](http://jeffgeerling.com/), author of [Ansible for DevOps](http://ansiblefordevops.com/).
