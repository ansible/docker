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

import os
import logging
import re
import json
import sys

from requests.exceptions import SSLError
from urlparse import urlparse
from logging import Handler, NOTSET
from ansible.module_utils.basic import *

HAS_DOCKER_PY = True

try:
    from docker import Client
    from docker.errors import APIError, TLSParameterError, NotFound
    from docker.tls import TLSConfig
    from docker.constants import DEFAULT_TIMEOUT_SECONDS, DEFAULT_DOCKER_API_VERSION
    from docker.utils.types import Ulimit, LogConfig
except ImportError:
    HAS_DOCKER_PY = False

DEFAULT_DOCKER_HOST = 'unix://var/run/docker.sock'
DEFAULT_TLS = False
DEFAULT_TLS_VERIFY = False

DOCKER_COMMON_ARGS = dict(
    docker_host=dict(type="str"),
    tls_hostname=dict(type="str"),
    api_version=dict(type="str"),
    timeout=dict(type='int'),
    cacert_path=dict(type='str'),
    cert_path=dict(type='str'),
    key_path=dict(type='str'),
    ssl_version=dict(type='str'),
    tls=dict(type='bool'),
    tls_verify=dict(type='bool'),
    debug=dict(type='bool', default=False),
    filter_logger=dict(type='bool', default=False),
    log_path=dict(type='str'),
    log_mode=dict(type='str', choices=['stderr', 'file', 'syslog'], default='file'),
)

DOCKER_MUTUALLY_EXCLUSIVE = [
    ['tls', 'tls_verify']
]

DOCKER_REQUIRED_TOGETHER = [
    ['cert_path', 'key_path']
]

DEFAULT_DOCKER_REGISTRY = 'https://index.docker.io/v1/'
EMAIL_REGEX = '[^@]+@[^@]+\.[^@]+'
BYTE_SUFFIXES = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']


if not HAS_DOCKER_PY:
    # No docker-py. Create a place holder client to allow
    # instantiation of AnsibleModule and proper error handing
    class Client(object):
        def __init__(self, **kwargs):
            pass


def human_to_bytes(number):
    if number is None:
        return 0

    if isinstance(number, int):
        return number

    if number[-1].isdigit():
        return int(number)

    if number[-1] == BYTE_SUFFIXES[0] and number[-2].isdigit():
        return int(number[:-1])

    i = 1
    for each in BYTE_SUFFIXES[1:]:
        if number[-len(each):] == BYTE_SUFFIXES[i]:
            return int(number[:-len(each)]) * (1024 ** i)
        i += 1

    raise ValueError("Failed to convert {0}. The suffix must be one of {1}".format(number,
                                                                                   ','.join(BYTE_SUFFIXES)))


class DockerBaseClass(object):

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def log(self, msg, pretty_print=False):
        if pretty_print:
            self.logger.debug(json.dumps(msg, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.logger.debug(msg)


class DockerSysLogHandler(Handler):

    def __init__(self, level=NOTSET, module=None):
        self.module = module
        super(DockerSysLogHandler, self).__init__(level)

    def emit(self, record):
        log_entry = self.format(record)
        self.module.debug(log_entry)


class AnsibleDockerClient(Client):

    def __init__(self, argument_spec=None, supports_check_mode=False, mutually_exclusive=None,
                 required_together=None, required_if=None):

        self.logger = logging.getLogger(self.__class__.__name__)

        merged_arg_spec = dict()
        merged_arg_spec.update(DOCKER_COMMON_ARGS)
        if argument_spec:
            merged_arg_spec.update(argument_spec)
            self.arg_spec = merged_arg_spec

        mutually_exclusive_params = []
        mutually_exclusive_params += DOCKER_MUTUALLY_EXCLUSIVE
        if mutually_exclusive:
            mutually_exclusive_params += mutually_exclusive

        required_together_params = []
        required_together_params += DOCKER_REQUIRED_TOGETHER
        if required_together:
            required_together_params += required_together

        self.module = AnsibleModule(
            argument_spec=merged_arg_spec,
            supports_check_mode=supports_check_mode,
            mutually_exclusive=mutually_exclusive_params,
            required_together=required_together_params,
            required_if=required_if)

        if not HAS_DOCKER_PY:
            self.fail("Failed to import docker-py. Try `pip install docker-py`")

        debug = self.module.params.get('debug')
        log_mode = self.module.params.get('log_mode')
        filter_logger = self.module.params.get('filter_logger')
        if debug and log_mode == 'syslog':
            handler = DockerSysLogHandler(level=logging.DEBUG, module=self.module)
            self.logger.addHandler(handler)
            logging.basicConfig(level=logging.DEBUG)
        elif debug and log_mode == 'file':
            log_path = self.module.params.get('log_path')
            logging.basicConfig(level=logging.DEBUG, filename=log_path)
        elif debug and log_mode == 'stderr':
            logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)

        if filter_logger:
            for h in logging.root.handlers:
                h.addFilter(logging.Filter(name=self.logger.name))

        self.check_mode = self.module.check_mode   
        self._connect_params = self._get_connect_params()

        try:
            super(AnsibleDockerClient, self).__init__(**self._connect_params)
        except APIError, exc:
            self.fail("Docker API error: {0}".format(exc))
        except Exception, exc:
            self.fail("Error connecting: {0}".format(exc))

    def log(self, msg, pretty_print=False):
        if pretty_print:
            self.logger.debug(json.dumps(msg, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.logger.debug(msg)
    
    def fail(self, msg):
        self.module.fail_json(msg=msg)

    @staticmethod
    def _get_value(param_name, param_value, env_variable, default_value):
        if param_value is not None:
            # take module parameter value
            if param_value in BOOLEANS_TRUE:
                return True
            if param_value in BOOLEANS_FALSE:
                return False
            return param_value

        if env_variable is not None:
            env_value = os.environ.get(env_variable)
            if env_value is not None:
                # take the env variable value
                if param_name == 'cert_path':
                    return os.path.join(env_value, 'cert.pem')
                if param_name == 'cacert_path':
                    return os.path.join(env_value, 'ca.pem')
                if param_name == 'key_path':
                    return os.path.join(env_value, 'key.pem')
                if env_value in BOOLEANS_TRUE:
                    return True
                if env_value in BOOLEANS_FALSE:
                    return False
                return env_value

        # take the default
        return default_value

    @property
    def auth_params(self):
        # Get authentication credentials.
        # Precedence: module parameters-> environment variables-> defaults.

        self.log('Getting credentials')

        params = dict()
        for key in DOCKER_COMMON_ARGS:
            params[key] = self.module.params.get(key)

        result = dict(
            docker_host=self._get_value('docker_host', params['docker_host'], 'DOCKER_HOST',
                                        DEFAULT_DOCKER_HOST),
            tls_hostname=self._get_value('tls_hostname', params['tls_hostname'],
                                        'DOCKER_TLS_HOSTNAME', 'localhost'),
            api_version=self._get_value('api_version', params['api_version'], 'DOCKER_API_VERSION',
                                        DEFAULT_DOCKER_API_VERSION),
            cacert_path=self._get_value('cacert_path', params['cacert_path'], 'DOCKER_CERT_PATH', None),
            cert_path=self._get_value('cert_path', params['cert_path'], 'DOCKER_CERT_PATH', None),
            key_path=self._get_value('key_path', params['key_path'], 'DOCKER_CERT_PATH', None),
            ssl_version=self._get_value('ssl_version', params['ssl_version'], 'DOCKER_SSL_VERSION', None),
            tls=self._get_value('tls', params['tls'], 'DOCKER_TLS', DEFAULT_TLS),
            tls_verify=self._get_value('tls_verfy', params['tls_verify'], 'DOCKER_TLS_VERIFY',
                                       DEFAULT_TLS_VERIFY),
            timeout=self._get_value('timeout', params['timeout'], 'DOCKER_TIMEOUT',
                                    DEFAULT_TIMEOUT_SECONDS),
        )

        if result['tls_hostname'] is None:
            # get default machine name from the url
            parsed_url = urlparse(result['docker_host'])
            if ':' in parsed_url.netloc:
                result['tls_hostname'] = parsed_url.netloc[:parsed_url.netloc.rindex(':')]
            else:
                result['tls_hostname'] = parsed_url

        return result

    def _get_tls_config(self, **kwargs):
        self.log("get_tls_config:")
        for key in kwargs:
            self.log("  {0}: {1}".format(key, kwargs[key]))
        try:
            tls_config = TLSConfig(**kwargs)
            return tls_config
        except TLSParameterError, exc:
           self.fail("TLS config error: {0}".format(exc))

    def _get_connect_params(self):
        auth = self.auth_params

        self.log("connection params:")
        for key in auth:
            self.log("  {0}: {1}".format(key, auth[key]))

        if auth['tls'] or auth['tls_verify']:
            auth['docker_host'] = auth['docker_host'].replace('tcp://', 'https://')

        if auth['tls'] and auth['cert_path'] and auth['key_path']:
            # TLS with certs and no host verification
            tls_config = self._get_tls_config(client_cert=(auth['cert_path'], auth['key_path']),
                                              verify=False,
                                              ssl_version=auth['ssl_version'])
            return dict(base_url=auth['docker_host'],
                        tls=tls_config,
                        version=auth['api_version'],
                        timeout=auth['timeout'])

        if auth['tls']:
            # TLS with no certs and not host verification
            tls_config = self._get_tls_config(verify=False,
                                              ssl_version=auth['ssl_version'])
            return dict(base_url=auth['docker_host'],
                        tls=tls_config,
                        version=auth['api_version'],
                        timeout=auth['timeout'])

        if auth['tls_verify'] and auth['cert_path'] and auth['key_path']:
            # TLS with certs and host verification
            if auth['cacert_path']:
                tls_config = self._get_tls_config(client_cert=(auth['cert_path'], auth['key_path']),
                                                  ca_cert=auth['cacert_path'],
                                                  verify=True,
                                                  assert_hostname=auth['tls_hostname'],
                                                  ssl_version=auth['ssl_version'])
            else:
                tls_config = self._get_tls_config(client_cert=(auth['cert_path'], auth['key_path']),
                                                  verify=True,
                                                  assert_hostname=auth['tls_hostname'],
                                                  ssl_version=auth['ssl_version'])

            return dict(base_url=auth['docker_host'],
                        tls=tls_config,
                        version=auth['api_version'],
                        timeout=auth['timeout'])

        if auth['tls_verify'] and auth['cacert_path']:
            # TLS with cacert only
            tls_config = self._get_tls_config(ca_cert=auth['cacert_path'],
                                              assert_hostname=auth['tls_hostname'],
                                              verify=True,
                                              ssl_version=auth['ssl_version'])
            return dict(base_url=auth['docker_host'],
                        tls=tls_config,
                        version=auth['api_version'],
                        timeout=auth['timeout'])

        if auth['tls_verify']:
            # TLS with verify and no certs
            tls_config = self._get_tls_config(verify=True,
                                              assert_hostname=auth['tls_hostname'],
                                              ssl_version=auth['ssl_version'])
            return dict(base_url=auth['docker_host'],
                        tls=tls_config,
                        version=auth['api_version'],
                        timeout=auth['timeout'])
        # No TLS
        return dict(base_url=auth['docker_host'],
                    version=auth['api_version'],
                    timeout=auth['timeout'])

    def _handle_ssl_error(self, error):
        match = re.match(r"hostname.*doesn\'t match (\'.*\')", str(error))
        if match:
            msg = "You asked for verification that Docker host name matches {0}. The actual hostname is {1}. " \
                "Most likely you need to set DOCKER_TLS_HOSTNAME or pass tls_hostname with a value of {1}. " \
                "You may also use TLS without verification by setting the tls parameter to true." \
                .format(self.auth_params['tls_hostname'], match.group(1))
            self.fail(msg)
        self.fail("SSL Exception: {0}".format(error))

    def get_container(self, name=None):
        '''
        Lookup a container and return the inspection results.
        '''
        if name is None:
            return None

        search_name = name
        if not name.startswith('/'):
            search_name = '/' + name

        result = None
        try:
            for container in self.containers(all=True):
                self.log("testing container: {0}".format(container['Names']))
                if search_name in container['Names']:
                    result = container
                    break
                if container['Id'].startswith(name):
                    result = container
                    break
                if container['Id'] == name:
                    result = container
                    break
        except SSLError, exc:
            self._handle_ssl_error(exc)
        except Exception, exc:
            self.fail("Error retrieving container list: {0}".format(exc))

        if result is not None:
            try:
                self.log("Inspecting container Id {0}".format(result['Id']))
                result = self.inspect_container(container=result['Id'])
                self.log("Completed container inspection")
            except Exception, exc:
                self.fail("Error inspecting container: {0}".format(exc))

        return result

    def find_image(self, name, tag="latest"):
        '''
        Lookup an image and return the inspection results.
        '''
        if not name:
            return None

        lookup = "{0}:{1}".format(name, tag)
        try:
            images = self.images(name=lookup)
        except Exception, exc:
            self.fail("Error getting image: {0}".format(str(exc)))

        if len(images) > 1:
            self.fail("Registry returned more than one result for {0}".format(lookup))

        if len(images) == 1:
            try:
                inspection = self.inspect_image(images[0]['Id'])
            except Exception, exc:
                self.fail("Error inspecting image {0} - {1}".format(lookup, str(exc)))
            inspection['Name'] = lookup
            return inspection

        return None

    def pull_image(self, name, tag="latest"):
        '''
        Pull an image
        '''
        try:
            self.log("Pulling image {0}:{1}".format(name, tag))
            for line in self.pull(name, tag=tag, stream=True):
                response = json.loads(line)
                self.log(response, pretty_print=True)
            return self.find_image(name, tag)
        except Exception, exc:
            self.fail("Error pulling image {0}:{1} - {2}".format(name, tag, str(exc)))


