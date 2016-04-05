#!/usr/bin/python
#
# (c) 2016 Olaf Kilian <olaf.kilian@symanex.com>
#          Chris Houseknecht, <house@redhat.com>
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

import base64
import logging

from ansible.module_utils.docker import *


DOCUMENTATION = '''
---
module: docker_login

short_description: Log into a Docker registry.

description:
    - Provides functionality similar to the "docker login" command.
    - Authenticate with a docker registry and add the credentials to your local Docker config file. Adding the
      credentials to the config files allows future connections to the registry using tools such as Ansible's Docker
      modules, the Docker CLI and docker-py without needing to provide credentials.
    - Running in check mode will perform the authentication without updating the config file.

options:
  registry_url:
    description:
      - The registry URL.
    default: "https://index.docker.io/v1/"
    aliases:
      - registry
      - url
  username:
    description:
      - The username for the registry account
    required: true
  password:
    description:
      - The plaintext password for the registry account
    required: true
  email:
    description:
      - The email address for the registry account. NOTE: private registries may not require this,
        but Docker Hub requires it.
    default: None
  reauthorize:
    description:
      - Refresh exiting authentication found in the configuration file.
    default: false
    aliases:
      - reauth
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

- name: Log into DockerHub
  docker_login:
    username: docker
    password: rekcod
    email: docker@docker.io

- name: Log into private registry and force re-authorization
  docker_login:
    registry: your.private.registry.io
    username: yourself
    password: secrets3
    reauthorize: yes

- name: Log into DockerHub using a custom config file
  docker_login:
    username: docker
    password: rekcod
    email: docker@docker.io
    config_path: /tmp/.mydockercfg

'''

RETURNS = '''
{
    "actions": [
        "Log into https://index.docker.io/v1/",
        "Updated config file /Users/chouseknecht/.docker/config.json with new authorization for https://index.docker.io/v1/"
    ],
    "changed": true,
    "check_mode": false,
    "results": {
        "Status": "Login Succeeded"
    }
}
'''


class LoginManager(DockerBaseClass):

    def __init__(self, client, results):

        super(LoginManager, self).__init__()

        self.client = client
        self.results = results
        parameters = self.client.module.params
        self.check_mode = self.client.check_mode

        self.registry_url = parameters.get('registry_url')
        self.username = parameters.get('username')
        self.password = parameters.get('password')
        self.email = parameters.get('email')
        self.reauthorize = parameters.get('reauthorize')
        self.config_path = parameters.get('config_path')

        self.login()

    def fail(self, msg):
        self.client.fail(msg)

    def login(self):
        '''
        Log into the registry with provided username/password. On success update the config
        file with the new authorization.

        :return: None
        '''

        if self.email and not re.match(EMAIL_REGEX, self.email):
            self.fail("Parameter error: the email address appears to be incorrect. Expecting it to match "
                      "/{0}/".format(EMAIL_REGEX))

        self.results['actions'].append("Logged into {0}".format(self.registry_url))
        self.log("Log into {0} with username {1}".format(self.registry_url, self.username))
        try:
            response = self.client.login(
                self.username,
                password=self.password,
                email=self.email,
                registry=self.registry_url,
                reauth=self.reauthorize,
                dockercfg_path=self.config_path
            )
        except Exception, exc:
            self.fail("Logging into {0} for user {1} failed - {2}".format(self.registry_url,
                                                                      self.username,
                                                                      str(exc)))
        self.results['results'] = response

        if not self.check_mode:
            self.update_config_file()

    def config_file_exists(self, path):
        if os.path.exists(path):
            self.log("Configuration file {0} exists".format(path))
            return True
        self.log("Configuration file {0} not found.".format(path))
        return False

    def create_config_file(self, path):
        '''
        Create a config file with a JSON blob containing an auths key.

        :return: None
        '''

        self.log("Creating docker config file {0}".format(path))
        config_path_dir = os.path.dirname(path)
        if not os.path.exists(config_path_dir):
            try:
                os.makedirs(config_path_dir)
            except Exception, exc:
                self.fail("Error: failed to create {0} - {1}".format(config_path_dir, str(exc)))
        self.write_config(path, dict(auths=dict()))

    def write_config(self, path, config):
        try:
            json.dump(config, open(path, "w"), indent=5, sort_keys=True)
        except Exception, exc:
            self.fail("Error: failed to write config to {0} - {1}".format(path, str(exc)))

    def update_config_file(self):
        '''
        If the authorization not stored in the config file or reauthorize is True,
        update the config file with the new authorization.
        
        :return: None
        '''

        path = os.path.expanduser(self.config_path)
        if not self.config_file_exists(path):
            self.create_config_file(path)

        try:
            # read the existing config
            config = json.load(open(path, "r"))
        except ValueError:
            self.log("Error reading config from {0}".format(path))
            config = dict()

        if not config.get('auths'):
            self.log("Adding auths dict to config.")
            config['auths'] = dict()

        if not config['auths'].get(self.registry_url):
            self.log("Adding registry_url {0} to auths.".format(self.registry_url))
            config['auths'][self.registry_url] = dict()

        encoded_credentials = dict(
            auth=base64.b64encode(self.username + b':' + self.password),
            email=self.email
        )

        if config['auths'][self.registry_url] != encoded_credentials or self.reauthorize:
            # Update the config file with the new authorization
            config['auths'][self.registry_url] = encoded_credentials
            self.log("Updating config file {0} with new authorization for {1}".format(path,
                                                                                      self.registry_url))
            self.results['actions'].append("Updated config file {0} with new authorization for {1}".format(
                path, self.registry_url))
            self.results['changed'] = True
            self.write_config(path, config)


def main():

    argument_spec=dict(
        registry_url=dict(type='str', required=False, default=DEFAULT_DOCKER_REGISTRY, aliases=['registry', 'url']),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        email=dict(type='str'),
        reauthorize=dict(type='bool', default=False, aliases=['reauth']),
        config_path=dict(type='str', default='~/.docker/config.json', aliases=['self.config_path',
                                                                               'dockercfg_path']),
        log_path=dict(type='str', default='docker_login.log')
    )

    required_if = [
        ('registry_url', DEFAULT_DOCKER_REGISTRY, ['email'])
    ]

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if
    )

    results = dict(
        changed=False,
        check_mode=client.check_mode,
        actions=[],
        results={}
    )

    LoginManager(client, results)
    client.module.exit_json(**results)

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
