#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.


from ansible.module_utils.docker_common import *
from ansible.module_utils.basic import *


class FileManager(DockerBaseClass):

    def __init__(self, client, results):

        super(FileManager, self).__init__()

        self.client = client
        self.results = results
        parameters = self.client.module.params
        self.check_mode = self.client.check_mode

        self.src = parameters.get('src'),
        self.dest = parameters.get('dest'),
        self.follow = parameters.get('follow')
        self.exec_module()

    def fail(self, msg):
        self.client.fail(msg)

    def exec_module(self):
        if



def main():
    argument_spec = dict(
        src=dict(type='str'),
        dest=dict(type='str'),
        follow=dcit(type='bool', default=False, aliases=['follow_links']),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    results = dict(
        changed=False,
        actions=[],
        files={}
    )

    FileManager(client, results)
    client.module.exit_json(**results)


if __name__ == '__main__':
    main()
