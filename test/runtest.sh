#!/bin/bash

rm ansible.log ; ANSIBLE_KEEP_REMOTE_FILES=1 ansible-playbook -vvvv lnmp_stack.yml
