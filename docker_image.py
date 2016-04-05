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

import logging

from ansible.module_utils.docker import *

try:
    from docker import auth
    from docker import utils
except:
    # missing docker-py handled in ansible.module_utils.docker
    pass

DOCUMENTATION = '''
---
module: docker_image
author: "Chris Houseknecht (@chouseknecht)"
version_added: "1.5"
short_description: manage docker images
description:
     - Create, check and remove docker images
options:
  path:
    description:
       - Path to directory with Dockerfile
    required: false
    default: null
    aliases: []
  dockerfile:
    description:
       - Dockerfile to use
    required: false
    default: Dockerfile
    version_added: "2.0"
  name:
    description:
       - Image name to work with
    required: true
    default: null
    aliases: []
  tag:
    description:
       - Image tag to work with
    required: false
    default: "latest"
    aliases: []
  nocache:
    description:
      - Do not use cache with building
    required: false
    default: false
    aliases: []
  docker_url:
    description:
      - URL of docker host to issue commands to
    required: false
    default: ${DOCKER_HOST} or unix://var/run/docker.sock
    aliases: []
  use_tls:
    description:
      - Whether to use tls to connect to the docker server.  "no" means not to
        use tls (and ignore any other tls related parameters). "encrypt" means
        to use tls to encrypt the connection to the server.  "verify" means to
        also verify that the server's certificate is valid for the server
        (this both verifies the certificate against the CA and that the
        certificate was issued for that host. If this is unspecified, tls will
        only be used if one of the other tls options require it.
    choices: [ "no", "encrypt", "verify" ]
    version_added: "2.0"
  tls_client_cert:
    description:
      - Path to the PEM-encoded certificate used to authenticate docker client.
        If specified tls_client_key must be valid
    default: ${DOCKER_CERT_PATH}/cert.pem
    version_added: "2.0"
  tls_client_key:
    description:
      - Path to the PEM-encoded key used to authenticate docker client. If
        specified tls_client_cert must be valid
    default: ${DOCKER_CERT_PATH}/key.pem
    version_added: "2.0"
  tls_ca_cert:
    description:
      - Path to a PEM-encoded certificate authority to secure the Docker connection.
        This has no effect if use_tls is encrypt.
    default: ${DOCKER_CERT_PATH}/ca.pem
    version_added: "2.0"
  tls_hostname:
    description:
      - A hostname to check matches what's supplied in the docker server's
        certificate.  If unspecified, the hostname is taken from the docker_url.
    default: Taken from docker_url
    version_added: "2.0"
  docker_api_version:
    description:
      - Remote API version to use. This defaults to the current default as
        specified by docker-py.
    default: docker-py default remote API version
    version_added: "2.0"
  state:
    description:
      - Set the state of the image
    required: false
    default: present
    choices: [ "present", "absent", "build" ]
    aliases: []
  timeout:
    description:
      - Set image operation timeout
    required: false
    default: 600
    aliases: []
requirements:
    - "python >= 2.6"
    - "docker-py"
    - "requests"
'''

EXAMPLES = '''
Build docker image if required. Path should contains Dockerfile to build image:

- hosts: web
  become: yes
  tasks:
  - name: check or build image
    docker_image: path="/path/to/build/dir" name="my/app" state=present

Build new version of image:

- hosts: web
  become: yes
  tasks:
  - name: check or build image
    docker_image: path="/path/to/build/dir" name="my/app" state=build

Remove image from local docker storage:

- hosts: web
  become: yes
  tasks:
  - name: remove image
    docker_image: name="my/app" state=absent

'''

import re
import os
from urlparse import urlparse

try:
    import json
except ImportError:
    import simplejson as json

try:
    from requests.exceptions import *
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import docker.client
    HAS_DOCKER_CLIENT = True
except ImportError:
    HAS_DOCKER_CLIENT = False

DEFAULT_DOCKER_API_VERSION = None
if HAS_DOCKER_CLIENT:
    try:
        from docker.errors import APIError as DockerAPIError
    except ImportError:
        from docker.client import APIError as DockerAPIError

    try:
        # docker-py 1.2+
        import docker.constants
        DEFAULT_DOCKER_API_VERSION = docker.constants.DEFAULT_DOCKER_API_VERSION
    except (ImportError, AttributeError):
        # docker-py less than 1.2
        DEFAULT_DOCKER_API_VERSION = docker.client.DEFAULT_DOCKER_API_VERSION


class ImageManager(DockerBaseClass):

    def __init__(self, client, results):
        super(ImageManager, self).__init__()
        self.client = client
        self.results = results
        parameters = self.client.module.params
        self.check_mode = self.client.check_mode

        self.archive_path = parameters.get('archive_path')
        self.config_path = parameters.get('config_path')
        self.container_limits = parameters.get('container_limits')
        self.dockerfile = parameters.get('dockerfile')
        self.force = parameters.get('force')
        self.load_path = parameters.get('load_path')
        self.name = parameters.get('name')
        self.nocache = parameters.get('nocache')
        self.path = parameters.get('path')
        self.pull = parameters.get('pull')
        self.push = parameters.get('push')
        self.repository = parameters.get('repository')
        self.rm = parameters.get('rm')
        self.state = parameters.get('state')
        self.tag = parameters.get('tag')
        self.http_timeout = parameters.get('http_timeout')

        if self.state == 'present':
            self.present()
        elif self.state == 'absent':
            self.absent()
        elif self.state == 'tagged':
            self.tagged()

    def fail(self, msg):
        self.client.fail(msg)

    def present(self):
        '''
        Handle state present
        '''
        image = self.client.find_image(name=self.name, tag=self.tag)

        if not image or self.force:
            if self.path:
                # build the image
                params = dict(
                    path=self.path,
                    tag=self.name,
                    rm=self.rm,
                    nocache=self.nocache,
                    stream=True,
                    timeout=self.http_timeout,
                    pull=self.pull,
                    forcerm=self.rm,
                    dockerfile=self.dockerfile,
                    decode=True
                )
                if self.tag:
                    params['tag'] = "{0}:{1}".format(self.name, self.tag)
                if self.container_limits:
                    params['container_limits'] = self.container_limits,
                self.log("Bulding image {0}".format(params['tag']))
                if not self.check_mode:
                    for line in self.client.build(**params):
                        self.log(line, pretty_print=True)
                self.results['changed'] = True
                self.results['actions'].append("Built image {0} from {1}".format(params['tag'], self.path))
                image = self.client.find_image(name=self.name, tag=self.tag)
                if image:
                    self.results['results'] = image

            elif self.load_path:
                # Load the image from an archive
                if not os.path.isfile(self.load_path):
                    self.fail("Error loading image {0}. Specified path {1} does not exist.".format(self.name,
                                                                                                   self.load_path))
                name = self.name
                if self.tag:
                    name = "{0}:{1}".format(self.name, self.tag)

                if not self.check_mode:
                    try:
                        self.log("Reading image data from {0}".format(self.load_path))
                        image_tar = open(self.load_path, 'r')
                        image_data = image_tar.read()
                        image_tar.close()
                    except Exception, exc:
                        self.fail("Error reading image data {0} - {1}".format(self.load_path, str(exc)))

                    try:
                        self.log("Loading image from {0}".format(self.load_path))
                        response = self.client.load_image(image_data)
                    except Exception, exc:
                        self.fail("Error loading image {0} - {1}".format(name, str(exc)))

                self.results['changed'] = True
                self.results['actions'].append("Loaded image {0} from {1}".format(name, self.load_path))
                image = self.client.find_image(self.name, self.tag)
                if image:
                    self.results['results'] = image

            else:
                # pull the image
                if not self.check_mode:
                    self.client.pull_image(self.name, tag=self.tag)

                self.results['changed'] = True
                self.results['actions'].append('Pulled image {0}:{1}'.format(self.name, self.tag))
                image = self.client.find_image(name=self.name, tag=self.tag)
                if image:
                    self.results['results'] = image

        if self.archive_path:
            self.archive_image(self.name, self.tag)

        if self.push:
            self.push_image(self.name, self.tag)

    def absent(self):
        '''
        Remove image
        '''
        image = self.client.find_image(name=self.name, tag=self.tag)
        if image:
            name = self.name
            if self.tag:
                name = "{0}:{1}".format(self.name, self.tag)
            if not self.check_mode:
                try:
                    self.client.remove_image(name, force=self.force)
                except Exception, exc:
                    self.fail("Error removing image {0} - {1}".format(name, str(exc)))

            self.results['changed'] = True
            self.results['actions'].append("Removed image {0}".format(name))

    def archive_image(self, name, tag):
        '''
        Archive image to a .tar file
        '''
        if not tag:
            tag = "latest"
        image = self.client.find_image(name=name, tag=tag)
        self.log("archive image:")
        self.log(image, pretty_print=True)
        if image:
            if not os.path.isfile(self.archive_path) or self.force:
                image_name = "{0}:{1}".format(name, tag)
                try:
                    self.log("Getting archive of image {0}".format(image_name))
                    image = self.client.get_image(image_name)
                except Exception, exc:
                    self.fail("Error getting image {0} - {1}".format(image_name, str(exc)))

                if not self.check_mode:
                    try:
                        image_tar = open(self.archive_path, 'w')
                        image_tar.write(image.data)
                        image_tar.close()
                    except Exception, exc:
                        self.fail("Error writing image archive {0} - {1}".format(self.archive_path, str(exc)))

                self.results['changed'] = True
                self.results['actions'].append('Archived image {0} to {1}'.format(image_name, self.archive_path))
                image = self.client.find_image(name=name, tag=tag)
                if image:
                    self.results['results'] = image

    def push_image(self, name, tag=None):
        '''
        Push image
        '''
        repository = name
        if not tag:
            repository, tag = utils.parse_repository_tag(name)
        registry, repo_name = auth.resolve_repository_name(repository)

        if registry:
            config = auth.load_config()
            if not auth.resolve_authconfig(config, registry):
                self.fail("Error: configuration for {0} not found. Try logging into {0} first.".format(registry))

        try:
            self.log("pushing image {0}".format(repository))
            status = None
            if not self.check_mode:
                for line in self.client.push(repository, tag=tag, stream=True):
                    response = json.loads(line)
                    self.log(response, pretty_print=True)
                    if response.get('errorDetail'):
                        # there was an error
                        raise Exception(response['errorDetail']['message'])
                    status = response.get('status')
            self.results['changed'] = True
            self.results['actions'].append("Pushed image {0} to {1}:{2}".format(self.name,
                                                                                self.repository,
                                                                                self.tag))
            image = self.client.find_image(name=repository, tag=tag)
            if image:
                self.results['results'] = image
            self.results['results']['push_status'] = status
        except Exception, exc:
            if re.search(r'unauthorized', str(exc)):
                self.fail("Error pushing image {0}: {1}. Does the repository exist?".format(repository, str(exc)))
            self.fail("Error pushing image {0}: {1}".format(repository, str(exc)))

    def tagged(self):
        '''
        Tag an image into a repository
        '''
        image = self.client.find_image(name=self.repository, tag=self.tag)
        if not image or self.force:
            try:
                self.log("tagging {0} to {1} with tag {2}".format(self.name, self.repository, self.tag))
                if not self.check_mode:
                    tag_status = self.client.tag(self.name, self.repository, tag=self.tag, force=self.force)
                    if not tag_status:
                        raise Exception("Tag operation failed.")
                self.results['changed'] = True
                self.results['actions'].append("Tagged image {0} to {1}:{2}".format(self.name,
                                                                                    self.repository,
                                                                                    self.tag))
                image = self.client.find_image(name=self.repository, tag=self.tag)
                if image:
                    self.results['results'] = image
            except Exception, exc:
                self.fail("Error: failed to tag image {0} - {1}".format(self.name, str(exc)))

            if self.push:
                self.log("push {0} with tag {1}".format(self.repository, self.tag))
                self.push_image(self.repository, self.tag)


def main():
    argument_spec = dict(
        archive_path=dict(type='str'),
        config_path=dict(type='str'),
        container_limits=dict(type='dict'),
        debug_file=dict(type='str', default='docker_image.log'),
        dockerfile=dict(type='str'),
        force=dict(type='bool', default=False),
        http_timeout=dict(type='int'),
        load_path=dict(type='str'),
        name=dict(type='str', required=True),
        nocache=dict(type='str', default=False),
        path=dict(type='str'),
        pull=dict(type='bool', default=True),
        push=dict(type='bool', default=False),
        repository=dict(type='str'),
        rm=dict(type='bool', default=True),
        state=dict(type='str', choices=['absent', 'present', 'tagged'], default='present'),
        tag=dict(type='str', default='latest'),
    )

    required_if = [
        ('state', 'tagged', ['repository', 'tag'])
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

    if client.module.params.get('debug'):
        logging.basicConfig(filename=client.module.params.get('debug_file'), level=logging.DEBUG)

    ImageManager(client, results)
    client.module.exit_json(**results)


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
