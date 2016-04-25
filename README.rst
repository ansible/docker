Docker Modules
==============

This is the development repo for Ansible's docker modules.

Requirements
-------------

- Python >= 2.6
- docker-py
- docker API >= 1.20

Running the Demo 
----------------

The simplest and quickets way to run the demo and see the docker modules in action is to run Ansible from source on your docker host machine.

Docker Host Machine
;;;;;;;;;;;;;;;;;;;

If you do not already have a Docker host machine, may we suggest `Atomic ADB <https://github.com/projectatomic/adb-atomic-developer-bundle>`_.
It's simple to get up and running on Linux, Mac OSX and Windows. Just follow the `install instrutions <https://github.com/projectatomic/adb-atomic-developer-bundle#how-do-i-install-and-run-the-atomic-developer-bundle-adb>`_

Environment Setup
;;;;;;;;;;;;;;;;;

Do the following on your Docker host:

- `Run Ansible from source <http://docs.ansible.com/ansible/intro_installation.html#running-from-source>`_.
- Clone this repo: ``git clone git@github.com:ansible/docker.git``
- Copy docker_common.py (from your clone of ansible/docker) to the lib/ansible/module_utils directory in your ansible/ansible repo clone. You can also use a sym link.
- Install mysql. You'll need the mysql CLI.

Run the Demo 
;;;;;;;;;;;;

Assuming you're running on Atomic host, do the following from inside your ansible/docker clone:

::

  $ cd test
  $ export DOCKER_API_VERSION="1.20"
  $ ansible-playbook -i inventory lnmp_stack.yml

