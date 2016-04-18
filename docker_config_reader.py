#!/usr/bin/python
#
# (c) 2016 Chris Houseknecht, <house@redhat.com>
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
#

DOCUMENTATION = '''
---
module: docker_config_reader

short_description: Read Docker CLI config file.

description:
     - Read your Docker CLI configuration file and verify it contains an entry for a given registry. If the registry
       is not found, the module will fail. If username, password and email are provided, the information will be
       verified against the values found in the configuration file, and if the values do not match, the module will
       fail.

options:
  registry_url:
    description:
      - The registry URL. Defaults to the Docker Hub URL.
    default: "https://index.docker.io/v1/"
    aliases:
      - registry
      - url
  username:
    description:
      - The username for the registry account.
  password:
    description:
      - The plaintext password for the registry account.
  email:
    description:
      - The email address for the registry account.
  config_path:
    description:
      - Custom path to the Docker CLI configuration file.
    default: ~/.docker/config.json
    aliases:
      - self.config_path
      - dockercfg_path

requirements:
    - python >= 2.6
    - docker-py >= 1.1.0

authors:
    - "Olaf Kilian <olaf.kilian@symanex.com>"
    - "Chris Houseknecht house@redhat.com"

version_added: "2.0"

'''

EXAMPLES = '''

- name: Verify configuration for Docker Hub
  docker_config:
    username: chouseknecht
    password: xnvDhTjSdcIB
    email: house@redhat.com

- name: Verify configuration for private registry
  docker_config:
    registry: https://registry.mycompany.com
    username: bsmith
    password: foobar

'''

RETURN = '''
changed:
    description:
        - Whether or not a change was made. Will always be false, as this modules does not modify the configuraiton
          file.
    returned: always
    type: bool
    sample: False
Results:
    description: Facts about the current state of the object.
    returned: always
    type: dict
    sample: {
        "status": "Succeeded in verifying ~/.docker/config.json in config file."
    }
'''


from ansible.module_utils.basic import *
from ansible.module_utils.docker_common import *

import base64


class ConfigReader(DockerBaseClass):

    def __init__(self, module, results):

        super(ConfigReader, self).__init__()

        self.results = results
        self.module = module
        parameters = module.params

        self.registry_url = parameters.get('registry_url')
        self.username = parameters.get('username')
        self.password = parameters.get('password')
        self.email = parameters.get('email')
        self.config_path = parameters.get('config_path')

        if self.username is not None and self.password is None:
            self.fail("Parameter error: password is required when passing a username value.")
        if self.password is not None and self.username is None:
            self.fail("Parameter error: username is required when passing a password value.")

        self.verify_configuration()

    def fail(self, msg):
        self.module.fail_json(msg=msg)

    def verify_configuration(self):
        '''
        Read the configuration file. Verify valid JSON. Check existance of registry and optionally
        verify username, password and email values.

        :return: None
        '''

        path = os.path.expanduser(self.config_path)

        if not os.path.exists(path):
            self.fail("Eror: configuraton file {0} not found.".format(path))

        try:
            config_file = open(path, "r")
            raw_config = config_file.read()
        except Exception, exc:
            self.fail("Error: failed to read configuration file {0}. Do you have access? - {1}".format(path, str(exc)))

        try:
            config = json.loads(raw_config)
        except Exception, exc:
            self.fail("Error: failed to load JSON from configuration file {0}. Check file contents. Is it valid "
                      "JSON? - ".format(path, str(exc)))

        if not config.get('auths'):
            self.fail("Error: auths key not found in configuration.")

        if not config['auths'].get(self.registry_url):
            self.fail("Error: no entries found for registry {0} in configuration file {1}".format(self.registry_url,
                                                                                                  path))

        if self.username and self.password:
            auth = base64.b64encode(self.username + b':' + self.password)
            if config['auths'][self.registry_url].get('auth') != auth:
                self.fail("Error: provided username and password do not match those found in the configuration "
                          "file for registry {0}.".format(self.registry_url))

        if self.email and config['auths'][self.registry_url].get('email') != self.email:
            self.fail("Error: provided email does not match the email address found in the configuration for "
                      "registry {0}.".format(self.registry_url))

        self.results['results'] = dict(status="Succeeded in verifying {0} in config file.".format(self.config_path))


def main():

    argument_spec=dict(
        registry_url=dict(required=False, default=DEFAULT_DOCKER_REGISTRY, aliases=['registry', 'url']),
        username=dict(type='str'),
        password=dict(type='str', no_log=True),
        email=dict(type='str'),
        config_path=dict(required=False, default='~/.docker/config.json', aliases=['self.config_path',
                                                                                             'dockercfg_path']),
        debug_file=dict(type='str', default='docker_config.log')
    )

    module = AnsibleModule(argument_spec=argument_spec)

    results = dict(
        changed=False,
        results={}
    )

    ConfigReader(module, results)
    module.exit_json(**results)

if __name__ == '__main__':
    main()
