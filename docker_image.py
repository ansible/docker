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

short_description: Manage docker images.

description:
     - Build, load or pull an image, making the image available for creating containers. Also supports tagging an
       image into a repository and archiving an image to a .tar file.

options:
  archive_path:
    description:
      - Use with state 'present' to archive an image to a .tar file.
  config_path:
    description:
      - Path to the Docker CLI config file.
    default: '~/.docker/config.json'
  dockerfile:
    description:
      - Use with state 'present' to provide an alternate name for the Dockerfile to use when building an image.
    default: Dockerfile
    version_added: "2.0"
  force:
    description:
      - Use with absent state to un-tag and remove all images matching the specified name. Use with states 'present'
        and 'tagged' to take action even when an image already exists. If archive_path is specified, the force option
        will cause an existing archive to be overwritten.
    default: false
  http_timeout:
    description:
      - Timeout for HTTP requests during the image build operation. Provide a positive integer value for the number of
        seconds.
  name:
    description:
      - Image name. Name format will be one of: name, repository/name, registry_server:port/name.
        When pushing or pulling an image the name can optionally include the tag by appending ':tag_name'.
    required: true
  path:
    description:
      - Use with state 'present' to build an image. Will be the path to a directory containing the context and
        Dockerfile for building an image.
    aliases:
      - build_path
  push:
    description:
      - Use with state present to always push an image to the registry. The image name must contain a repository
        path and optionally a registry. For example: registry.ansible.com/user_a/repository
    default: false
  pull:
    description:
      - When building an image downloads any updates to the FROM image in Dockerfiles.
    default: true
  rm:
    description:
      - Remove intermediate containers after build.
    default: true
  nocache:
    description:
      - Do not use cache when building an image.
    default: false
  repository:
    description:
      - Use with state tagged to provide the full path to the repository.
  state:
    description:
      - Make assertions about the state of an image.
      - When 'absent' an image will be removed. Use the force option to un-tag and remove all images
        matching the provided name.
      - When 'present' check if an image exists using the provided name and tag. If the image is not found or the
        force option is used, the image will either be pulled, built or loaded. By default the image will be pulled
        from Docker Hub. To build the image, provide a path value set to a directory containing a context and
        Dockerfile. To load an image, specify load_path to provide a path to an archive file.
      - Use 'tagged' to tag an image into a repository. Provide a repository value containing the repository path. Use
        the force option to replace an existing image.
    default: present
    choices:
      - absent
      - present
      - tagged
  tag:
    description:
      - Used to select an image when pulling. Will be added to the image when pushing, tagging or building. Defaults to
       'latest' when pulling an image. Required when tagging.
    default: latest

requirements:
  - "python >= 2.6"
  - "docker-py"

authors:

'''

EXAMPLES = '''

- name: pull an image
  docker_image:
    name: pacur/centos-7

- name: Tag to repository in private registry
  docker_image:
    name: pacur/centos-7
    state: tagged
    repository: registry.ansible.com/chouseknecht/centos_images
    tag: 7.0
    push: yes

- name: Remove image
  docker_image:
    state: absent
    name: registry.ansible.com/chouseknecht/sinatra
    tag: v1

- name: Build an image and archive it
  docker_image:
    path: ./sinatra
    name: registry.ansible.com/chouseknecht/sinatra
    tag: v1

- name: Archive image
  docker_image:
    name: registry.ansible.com/chouseknecht/sinatra
    tag: v1
    archive_path: my_sinatra.tar

- name: Load image from archive
  docker_image:
    name: registry.ansible.com/chouseknecht/sinatra
    tag: v1
    load_path: my_sinatra.tar

'''


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

        if self.state in ['present', 'build']:
            self.present()
        elif self.state == 'absent':
            self.absent()
        elif self.state == 'tagged':
            self.tagged()

    def fail(self, msg):
        self.client.fail(msg)

    def present(self):
        '''
        Handles state = 'present', which includes building, loading or pulling an image,
        depending on user provided parameters.

        :returns None
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
                self.log("Building image {0}".format(params['tag']))
                if not self.check_mode:
                    self.results['actions'].append("Built image {0} from {1}".format(params['tag'], self.path))
                    for line in self.client.build(**params):
                        self.log(line, pretty_print=True)
                self.results['changed'] = True
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
                    self.results['actions'].append("Loaded image {0} from {1}".format(name, self.load_path))
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
                image = self.client.find_image(self.name, self.tag)
                if image:
                    self.results['results'] = image

            else:
                # pull the image
                if not self.check_mode:
                    self.results['actions'].append('Pulled image {0}:{1}'.format(self.name, self.tag))
                    self.client.pull_image(self.name, tag=self.tag)

                self.results['changed'] = True
                image = self.client.find_image(name=self.name, tag=self.tag)
                if image:
                    self.results['results'] = image

        if self.archive_path:
            self.archive_image(self.name, self.tag)

        if self.push:
            self.push_image(self.name, self.tag)

    def absent(self):
        '''
        Handles state = 'absent', which removes an image.

        :return None
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
        Archive an image to a .tar file. Called when archive_path is passed.

        :param name - name of the image. Type: str
        :return None
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
                    self.results['actions'].append('Archived image {0} to {1}'.format(image_name, self.archive_path))
                    try:
                        image_tar = open(self.archive_path, 'w')
                        image_tar.write(image.data)
                        image_tar.close()
                    except Exception, exc:
                        self.fail("Error writing image archive {0} - {1}".format(self.archive_path, str(exc)))

                self.results['changed'] = True
                image = self.client.find_image(name=name, tag=tag)
                if image:
                    self.results['results'] = image

    def push_image(self, name, tag=None):
        '''
        Push an image to a repository.

        :param name - name of the image to push. Type: str
        :param tag - use a specific tag. Type: str
        :return: None
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
                self.results['actions'].append("Pushed image {0} to {1}:{2}".format(self.name,
                                                                                    self.repository,
                                                                                    self.tag))
                for line in self.client.push(repository, tag=tag, stream=True):
                    response = json.loads(line)
                    self.log(response, pretty_print=True)
                    if response.get('errorDetail'):
                        # there was an error
                        raise Exception(response['errorDetail']['message'])
                    status = response.get('status')
            self.results['changed'] = True
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
        Handle state = 'tagged' to tag an image into a repository.

        :return None
        '''
        image = self.client.find_image(name=self.repository, tag=self.tag)
        if not image or self.force:
            try:
                self.log("tagging {0} to {1} with tag {2}".format(self.name, self.repository, self.tag))
                self.results['changed'] = True
                if not self.check_mode:
                    self.results['actions'].append("Tagged image {0} to {1}:{2}".format(self.name,
                                                                                        self.repository,
                                                                                        self.tag))
                    tag_status = self.client.tag(self.name, self.repository, tag=self.tag, force=self.force)
                    if not tag_status:
                        raise Exception("Tag operation failed.")
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
        dockerfile=dict(type='str'),
        force=dict(type='bool', default=False),
        http_timeout=dict(type='int'),
        load_path=dict(type='str'),
        name=dict(type='str', required=True),
        nocache=dict(type='str', default=False),
        path=dict(type='str', aliases=['build_path']),
        pull=dict(type='bool', default=True),
        push=dict(type='bool', default=False),
        repository=dict(type='str'),
        rm=dict(type='bool', default=True),
        state=dict(type='str', choices=['absent', 'present', 'tagged'], default='present'),
        tag=dict(type='str', default='latest'),
        log_file=dict(type='str', default='docker_image.log'),
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

    ImageManager(client, results)
    client.module.exit_json(**results)


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
