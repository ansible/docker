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

DOCUMENTATION = '''
---
module: docker_container
version_added: "2.1.0"
short_description: manage docker containers
description:
  - Manage the life cycle of docker containers.
options:
  count:
    description:
      - Number of matching containers that should be in the desired state.
    default: 1
  image:
    description:
      - Container image used to match and launch containers.
    required: true
  pull:
    description:
      - Control when container images are updated from the C(docker_url) registry.
        If "missing," images will be pulled only when missing from the host;
        if '"always," the registry will be checked for a newer version of the
        image' each time the task executes.
    default: missing
    choices: [ "missing", "always" ]
    version_added: "1.9"
  entrypoint:
    description:
      - Corresponds to ``--entrypoint`` option of ``docker run`` command and
        ``ENTRYPOINT`` directive of Dockerfile.
        Used to match and launch containers.
    default: null
    required: false
    version_added: "2.1"
  command:
    description:
      - Command used to match and launch containers.
    default: null
  name:
    description:
      - Name used to match and uniquely name launched containers. Explicit names
        are used to uniquely identify a single container or to link among
        containers. Mutually exclusive with a "count" other than "1".
    default: null
    version_added: "1.5"
  published_ports:
    description:
      - "List containing private to public port mapping specification.
        Use docker 'CLI-style syntax: C(8000), C(9000:8000), or C(0.0.0.0:9000:8000)'
        where 8000 is a container port, 9000 is a host port, and 0.0.0.0 is - a host interface.
        The container ports need to be exposed either in the Dockerfile or via the C(expose) option."
  expose:
    description:
      - List of additional container ports to expose for port mappings or links.
        If the port is already exposed using EXPOSE in a Dockerfile, you don't
        need to expose it again.
    default: null
    version_added: "1.5"
  publish_all_ports:
    description:
      - Publish all exposed ports to the host interfaces.
    default: false
    version_added: "1.5"
  volumes:
    description:
      - List of volumes to mount within the container
      - 'Use docker CLI-style syntax: C(/host:/container[:mode])'
      - You can specify a read mode for the mount with either C(ro) or C(rw).
        Starting at version 2.1, SELinux hosts can additionally use C(z) or C(Z)
        mount options to use a shared or private label for the volume.
    default: null
  volumes_from:
    description:
      - List of names of containers to mount volumes from.
    default: null
  links:
    description:
      - List of other containers to link within this container with an optional
      - 'alias. Use docker CLI-style syntax: C(redis:myredis).'
    default: null
    version_added: "1.5"
  devices:
    description:
      - List of host devices to expose to container
    default: null
    required: false
    version_added: "2.1"
  log_driver:
    description:
      - You can specify a different logging driver for the container than for the daemon.
        "json-file" Default logging driver for Docker. Writes JSON messages to file.
        docker logs command is available only for this logging driver.
        "none" disables any logging for the container.
        "syslog" Syslog logging driver for Docker. Writes log messages to syslog.
        docker logs command is not available for this logging driver.
        "journald" Journald logging driver for Docker. Writes log messages to "journald".
        "gelf" Graylog Extended Log Format (GELF) logging driver for Docker. Writes log messages to a GELF endpoint likeGraylog or Logstash.
        "fluentd" Fluentd logging driver for Docker. Writes log messages to "fluentd" (forward input).
        "awslogs" (added in 2.1) Awslogs logging driver for Docker. Writes log messages to AWS Cloudwatch Logs.
        If not defined explicitly, the Docker daemon's default ("json-file") will apply.
        Requires docker >= 1.6.0.
    required: false
    default: json-file
    choices:
      - json-file
      - none
      - syslog
      - journald
      - gelf
      - fluentd
      - awslogs
    version_added: "2.0"
  log_opt:
    description:
      - Additional options to pass to the logging driver selected above. See Docker `log-driver
        <https://docs.docker.com/reference/logging/overview/>` documentation for more information.
        Requires docker >=1.7.0.
    required: false
    default: null
    version_added: "2.0"
  memory_limit:
    description:
      - RAM allocated to the container as a number of bytes or as a human-readable
        string like "512MB". Leave as "0" to specify no limit.
    default: 0
  docker_url:
    description:
      - URL of the host running the docker daemon. This will default to the env
        var DOCKER_HOST if unspecified.
    default: ${DOCKER_HOST} or unix://var/run/docker.sock
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
    version_added: "1.9"
  tls_client_cert:
    description:
      - Path to the PEM-encoded certificate used to authenticate docker client.
        If specified tls_client_key must be valid
    default: ${DOCKER_CERT_PATH}/cert.pem
    version_added: "1.9"
  tls_client_key:
    description:
      - Path to the PEM-encoded key used to authenticate docker client. If
        specified tls_client_cert must be valid
    default: ${DOCKER_CERT_PATH}/key.pem
    version_added: "1.9"
  tls_ca_cert:
    description:
      - Path to a PEM-encoded certificate authority to secure the Docker connection.
        This has no effect if use_tls is encrypt.
    default: ${DOCKER_CERT_PATH}/ca.pem
    version_added: "1.9"
  tls_hostname:
    description:
      - A hostname to check matches what's supplied in the docker server's
        certificate.  If unspecified, the hostname is taken from the docker_url.
    default: Taken from docker_url
    version_added: "1.9"
  docker_api_version:
    description:
      - Remote API version to use. This defaults to the current default as
        specified by docker-py.
    default: docker-py default remote API version
    version_added: "1.8"
  docker_user:
    description:
      - Username or UID to use within the container
    required: false
    default: null
    version_added: "2.0"
  username:
    description:
      - Remote API username.
    default: null
  password:
    description:
      - Remote API password.
    default: null
  email:
    description:
      - Remote API email.
    default: null
  hostname:
    description:
      - Container hostname.
    default: null
  domainname:
    description:
      - Container domain name.
    default: null
  env:
    description:
      - Pass a dict of environment variables to the container.
    default: null
  env_file:
    version_added: "2.1"
    description:
      - Pass in a path to a file with environment variable (FOO=BAR).
        If a key value is present in both explicitly presented (i.e. as 'env')
        and in the environment file, the explicit value will override.
        Requires docker-py >= 1.4.0.
    default: null
    required: false
  dns:
    description:
      - List of custom DNS servers for the container.
    required: false
    default: null
  detach:
    description:
      - Enable detached mode to leave the container running in background. If
        disabled, fail unless the process exits cleanly.
    default: true
  signal:
    version_added: "2.0"
    description:
      - With the state "killed", you can alter the signal sent to the
        container.
    required: false
    default: KILL
  state:
    description:
      - Assert the container's desired state. "present" only asserts that the
        matching containers exist. "started" asserts that the matching
        containers both exist and are running, but takes no action if any
        configuration has changed. "reloaded" (added in Ansible 1.9) asserts that all matching
        containers are running and restarts any that have any images or
        configuration out of date. "restarted" unconditionally restarts (or
        starts) the matching containers. "stopped" and '"killed" stop and kill
        all matching containers. "absent" stops and then' removes any matching
        containers.
    required: false
    default: started
    choices:
      - present
      - started
      - reloaded
      - restarted
      - stopped
      - killed
      - absent
  privileged:
    description:
      - Whether the container should run in privileged mode or not.
    default: false
  lxc_conf:
    description:
      - LXC configuration parameters, such as C(lxc.aa_profile:unconfined).
    default: null
  stdin_open:
    description:
      - Keep stdin open after a container is launched.
    default: false
    version_added: "1.6"
  tty:
    description:
      - Allocate a pseudo-tty within the container.
    default: false
    version_added: "1.6"
  net:
    description:
      - 'Network mode for the launched container: bridge, none, container:<name|id>'
      - or host. Requires docker >= 0.11.
    default: false
    version_added: "1.8"
  pid:
    description:
      - Set the PID namespace mode for the container (currently only supports 'host'). Requires docker-py >= 1.0.0 and docker >= 1.5.0
    required: false
    default: None
    aliases: []
    version_added: "1.9"
  registry:
    description:
      - Remote registry URL to pull images from.
    default: DockerHub
    aliases: []
    version_added: "1.8"
  read_only:
    description:
      - Mount the container's root filesystem as read only
    default: null
    aliases: []
    version_added: "2.0"
  restart_policy:
    description:
      - Container restart policy.
      - The 'unless-stopped' choice is only available starting in Ansible 2.1 and for Docker 1.9 and above.
    choices: ["no", "on-failure", "always", "unless-stopped"]
    default: null
    version_added: "1.9"
  restart_policy_retry:
    description:
      - Maximum number of times to restart a container. Leave as "0" for unlimited
        retries.
    default: 0
    version_added: "1.9"
  extra_hosts:
    version_added: "2.0"
    description:
    - Dict of custom host-to-IP mappings to be defined in the container
  insecure_registry:
    description:
      - Use insecure private registry by HTTP instead of HTTPS. Needed for
        docker-py >= 0.5.0.
    default: false
    version_added: "1.9"
  cpu_set:
    description:
      - CPUs in which to allow execution. Requires docker-py >= 0.6.0.
    required: false
    default: null
    version_added: "2.0"
  cap_add:
    description:
      - Add capabilities for the container. Requires docker-py >= 0.5.0.
    required: false
    default: false
    version_added: "2.0"
  cap_drop:
    description:
      - Drop capabilities for the container. Requires docker-py >= 0.5.0.
    required: false
    default: false
    aliases: []
    version_added: "2.0"
  labels:
    description:
      - Set container labels. Requires docker >= 1.6 and docker-py >= 1.2.0.
    required: false
    default: null
    version_added: "2.1"
  stop_timeout:
    description:
      - How many seconds to wait for the container to stop before killing it.
    required: false
    default: 10
    version_added: "2.0"
  timeout:
    description:
      - Docker daemon response timeout in seconds.
    required: false
    default: 60
    version_added: "2.1"
  cpu_shares:
    description:
      - CPU shares (relative weight). Requires docker-py >= 0.6.0.
    required: false
    default: 0
    version_added: "2.1"
  ulimits:
    description:
      - ulimits, list ulimits with name, soft and optionally
        hard limit separated by colons. e.g. nofile:1024:2048
        Requires docker-py >= 1.2.0 and docker >= 1.6.0
    required: false
    default: null
    version_added: "2.1"

author:
    - "Cove Schneider (@cove)"
    - "Joshua Conner (@joshuaconner)"
    - "Pavel Antonov (@softzilla)"
    - "Thomas Steinbach (@ThomasSteinbach)"
    - "Philippe Jandot (@zfil)"
    - "Daan Oosterveld (@dusdanig)"
requirements:
    - "python >= 2.6"
    - "docker-py >= 0.3.0"
    - "The docker server >= 0.10.0"
'''

EXAMPLES = '''
# Containers are matched either by name (if provided) or by an exact match of
# the image they were launched with and the command they're running. The module
# can accept either a name to target a container uniquely, or a count to operate
# on multiple containers at once when it makes sense to do so.

# Ensure that a data container with the name "mydata" exists. If no container
# by this name exists, it will be created, but not started.

- name: data container
  docker:
    name: mydata
    image: busybox
    state: present
    volumes:
    - /data

# Ensure that a Redis server is running, using the volume from the data
# container. Expose the default Redis port.

- name: redis container
  docker:
    name: myredis
    image: redis
    command: redis-server --appendonly yes
    state: started
    expose:
    - 6379
    volumes_from:
    - mydata

# Ensure that a container of your application server is running. This will:
# - pull the latest version of your application image from DockerHub.
# - ensure that a container is running with the specified name and exact image.
#   If any configuration options have changed, the existing container will be
#   stopped and removed, and a new one will be launched in its place.
# - link this container to the existing redis container launched above with
#   an alias.
# - grant the container read write permissions for the host's /dev/sda device
#   through a node named /dev/xvda
# - bind TCP port 9000 within the container to port 8080 on all interfaces
#   on the host.
# - bind UDP port 9001 within the container to port 8081 on the host, only
#   listening on localhost.
# - specify 2 ip resolutions.
# - set the environment variable SECRET_KEY to "ssssh".

- name: application container
  docker:
    name: myapplication
    image: someuser/appimage
    state: reloaded
    pull: always
    links:
    - "myredis:aliasedredis"
    devices:
    - "/dev/sda:/dev/xvda:rwm"
    ports:
    - "8080:9000"
    - "127.0.0.1:8081:9001/udp"
    extra_hosts:
      host1: "192.168.0.1"
      host2: "192.168.0.2"
    env:
        SECRET_KEY: ssssh

# Ensure that exactly five containers of another server are running with this
# exact image and command. If fewer than five are running, more will be launched;
# if more are running, the excess will be stopped.

- name: load-balanced containers
  docker:
    state: reloaded
    count: 5
    image: someuser/anotherappimage
    command: sleep 1d

# Unconditionally restart a service container. This may be useful within a
# handler, for example.

- name: application service
  docker:
    name: myservice
    image: someuser/serviceimage
    state: restarted

# Stop all containers running the specified image.

- name: obsolete container
  docker:
    image: someuser/oldandbusted
    state: stopped

# Stop and remove a container with the specified name.

- name: obsolete container
  docker:
    name: ohno
    image: someuser/oldandbusted
    state: absent

# Example Syslogging Output

- name: myservice container
  docker:
    name: myservice
    image: someservice/someimage
    state: reloaded
    log_driver: syslog
    log_opt:
      syslog-address: tcp://my-syslog-server:514
      syslog-facility: daemon
      syslog-tag: myservice
'''

import logging

from ansible.module_utils.docker_common import *

try:
    from docker import auth
    from docker import utils
    from docker.utils.types import Ulimit
except:
    # missing docker-py handled in ansible.module_utils.docker
    pass


REQUIRES_CONVERSION_TO_BYTES = [
    'memory',
    'memory_reservation',
    'memory_swap',
    'shm_size'
]


class TaskParameters(DockerBaseClass):
    '''
    Access and parse module parameters
    '''

    def __init__(self, client):
        super(TaskParameters, self).__init__()
        self.client = client

        self.blkio_weight = None
        self.capabilities = None
        self.command = None
        self.cpu_period = None
        self.cpu_quota = None
        self.cpuset_cpus = None
        self.cpuset_mems = None
        self.cpu_shares = None
        self.detach = None
        self.devices = None
        self.dns_servers = None
        self.dns_opts = None
        self.dns_search_domains = None
        self.env = None
        self.entrypoint = None
        self.etc_hosts = None
        self.exposed_ports = None
        self.force_kill = None
        self.groups = None
        self.hostname = None
        self.image = None
        self.interactive = None
        self.ipc_mode = None
        self.keep_volumes = None
        self.kernel_memory = None
        self.kill_signal = None
        self.labels = None
        self.links = None
        self.log_driver = None
        self.log_options = None
        self.mac_address = None
        self.memory = None
        self.memory_reservation = None
        self.memory_swap = None
        self.memory_swappiness = None
        self.name = None
        self.network_mode = None
        self.networks = None
        self.oom_killer = None
        self.paused = None
        self.pid_mode = None
        self.privileged = None
        self.pull = None
        self.read_only = None
        self.recreate = None
        self.restart = None
        self.restart_retries = None
        self.shm_size = None
        self.security_opts = None
        self.state = None
        self.stop_signal = None
        self.stop_timeout = None
        self.trust_image_content = None
        self.tty = None
        self.user = None
        self.uts = None
        self.volumes = None
        self.volumes_from = None
        self.volume_driver = None
        self.debug = None
        self.debug_file = None

        for key, value in client.module.params.iteritems():
            setattr(self, key, value)

        for param_name in REQUIRES_CONVERSION_TO_BYTES:
            if client.module.params.get(param_name):
                try:
                    setattr(self, param_name, human_to_bytes(client.module.params.get(param_name)))
                except ValueError, exc:
                    self.fail("Failed to convert {0} to bytes: {1}".format(param_name, exc))

        self.ports = self._parse_exposed_ports()
        self.published_ports = self._parse_publish_ports()
        self.publish_all_ports = None
        if self.published_ports == 'all':
            self.publish_all_ports = True
            self.published_ports = None

        self.links = self._parse_links()

        if self.restart_policy is not None:
            self.restart_policy = dict(Name=self.restart_policy,
                                       MaximumRetryCount=self.restart_retries)
        self.ulimits = self._parse_ulimits()
        self.log_config = self._parse_log_config()
        self.exp_links = None
        self.volume_binds = self._parse_volumes()

    def fail(self, msg):
        self.client.module.fail_json(msg=msg)

    @property
    def update_parameters(self):
        '''
        Returns parameters used to update a container
        '''

        update_parameters = dict(
            blkio_weight='blkio_weight',
            cpu_period='cpu_period',
            cpu_quota='cpu_quota',
            cpu_shares='cpu_shares',
            cpuset_cpus='cpuset_cpus',
            mem_limit='memory',
            mem_reservation='mem_reservation',
            memswap_limit='memory_swap',
            kernel_memory='kernel_memory'
        )
        result = dict()
        for key, value in update_parameters.iteritems():
            if getattr(self, value, None) is not None:
                result[key] = getattr(self, value)
        return result

    @property
    def create_parameters(self):
        '''
        Returns parameters used to create a container
        '''
        create_params = dict(
            image='image',
            command='command',
            hostname='hostname',
            user='user',
            detach='detach',
            stdin_open='interactive',
            tty='tty',
            ports='ports',
            environment='env',
            dns='dns_servers',
            name='name',
            entrypoint='entrypoint',
            cpu_shares='cpu_shares',
            mac_address='mac_address',
            labels='labels',
            stop_signal='stop_signal',
            volume_driver='volume_driver',
        )

        result = dict(
            host_config=self._host_config(),
            volumes=self._get_mounts(),
        )

        for key, value in create_params.iteritems():
            if getattr(self, value, None) is not None:
                result[key] = getattr(self, value)

        return result

    def _get_mounts(self):
        result = []
        if self.volumes:
            for vol in self.volumes:
                host, container = vol.split(':')
                result.append(host)
        return result

    def _host_config(self):
        '''
        Returns parameters used to create a HostConfig object
        '''

        host_config_params=dict(
            port_bindings='published_ports',
            publish_all_ports='pubish_all_ports',
            links='links',
            privileged='privileged',
            dns='dns_servers',
            dns_search='dns_search_domains',
            binds='volume_binds',
            volumes_from='volumes_from',
            network_mode='network_mode',
            restart_policy='restart_policy',
            cap_add='capabilities',
            extra_hosts='etc_hosts',
            read_only='read_only',
            ipc_mode='ipc_mode',
            security_opt='security_opts',
            ulimits='ulimits',
            log_config='log_config',
            mem_limit='memory',
            memswap_limit='memory_swap',
            mem_swappiness='memory_swappiness',
            shm_size='shm_size',
            group_add='groups',
            devices='devices',
            pid_mode='pid_mode'
        )
        params = dict()
        for key, value in host_config_params.iteritems():
            if getattr(self, value, None) is not None:
                params[key] = getattr(self, value)
        return self.client.create_host_config(**params)

    def _parse_publish_ports(self):
        '''
        Parse ports from docker CLI syntax
        '''
        if self.published_ports is None:
            return None

        if 'all' in self.published_ports:
            return 'all'

        binds = {}
        for port in self.published_ports:
            parts = str(port).split(':')
            container_port = parts[-1]
            if '/' not in container_port:
                container_port = int(parts[-1])

            p_len = len(parts)
            if p_len == 1:
                bind = ('0.0.0.0',)
            elif p_len == 2:
                bind = ('0.0.0.0', int(parts[0]))
            elif p_len == 3:
                bind = (parts[0], int(parts[1])) if parts[1] else (parts[0],)

            if container_port in binds:
                old_bind = binds[container_port]
                if isinstance(old_bind, list):
                    old_bind.append(bind)
                else:
                    binds[container_port] = [binds[container_port], bind]
            else:
                binds[container_port] = bind
        return binds

    def _parse_volumes(self):
        '''
        Convert volumes parameter to host_config bind format.

        https://docker-py.readthedocs.org/en/latest/volumes/

        :return: array of binds
        '''
        results = dict()
        if self.volumes:
            for vol in self.volumes:
                if len(vol.split(':')) == 3:
                    host, container, mode = vol.split(':')
                else:
                    host, container, mode = vol.split(':') + ['rw']
                results[host] = dict(
                    bind=container,
                    mode=mode
                )
        return results

    def _parse_exposed_ports(self):
        '''
        Parse exposed ports from docker CLI-style ports syntax.
        '''
        if self.exposed_ports is None:
            return None

        exposed = []
        for port in self.exposed_ports:
            port = str(port).strip()
            if port.endswith('/tcp') or port.endswith('/udp'):
                port_with_proto = tuple(port.split('/'))
            else:
                # assume tcp protocol if not specified
                port_with_proto = (port, 'tcp')
            exposed.append(port_with_proto)
        return exposed

    def _parse_links(self):
        '''
        Turn links into a dictionary
        '''
        if self.links is None:
            return None

        links = {}
        for link in self.links:
            parsed_link = link.split(':', 1)
            if len(parsed_link) == 2:
                links[parsed_link[0]] = parsed_link[1]
            else:
                links[parsed_link[0]] = parsed_link[0]
        return links

    def _parse_ulimits(self):
        '''
        Turn ulimits into a dictionary
        '''
        if self.ulimits is None:
            return None

        results = []
        for limit in self.ulimits:
            limits = dict()
            pieces = limit.split(':')
            if len(pieces) >= 2:
                limits['name'] = pieces[0]
                limits['soft'] = int(pieces[1])
            if len(pieces) == 3:
                limits['hard'] = int(pieces[2])
            try:
                results.append(Ulimit(**limits))
            except ValueError, exc:
                self.fail("Error parsing ulimits value {0} - {1}".format(limit, exc))
        return results

    def _parse_log_config(self):
        '''
        Create a LogConfig object
        '''
        if self.log_driver is None:
            return None

        options = dict(
            Type=self.log_driver,
            Config = dict()
        )

        if self.log_options is not None:
            options['Config'] = self.log_opts

        try:
            return LogConfig(**options)
        except ValueError, exc:
            self.fail('Error parsing logging options - {0}'.format(exc))


class Container(DockerBaseClass):
    
    def __init__(self, container, parameters):
        super(Container, self).__init__()
        self.raw = container
        self.Id = None
        self.container = container
        if container:
            self.Id = container['Id']
            self.Image = container['Image']
        self.log(self.container, pretty_print=True)
        self.parameters = parameters
        self.parameters.expected_links = None
        self.parameters.expected_ports = None
        self.parameters.expected_exposed = None
        self.parameters.expected_volumes = None
        self.parameters.expected_ulimits = None
        self.parameters.expected_etc_hosts = None
        self.parameters.expected_env = None

    def fail(self, msg):
        self.parameters.client.module.fail_json(msg=msg)

    @property
    def found(self):
        return True if self.container else False

    @property
    def running(self):
        if self.container and self.container.get('State'):
            if self.container['State']['Running'] and self.container['State']['Status'] == 'running':
                return True
        return False

    def has_different_configuration(self, image):
        '''
        Diff parameters vs existing container config. Returns tuple: (True | False, List of differences)
        '''
        self.log('Starting has_different_configuration')
        self.parameters.expected_entrypoint = self._get_expected_entrypoint(image)
        self.parameters.expected_links = self._get_expected_links()
        self.parameters.expected_ports = self._get_expected_ports()
        self.parameters.expected_exposed = self._get_expected_exposed(image)
        self.parameters.expected_volumes = self._get_expected_volumes(image)
        self.parameters.expected_ulimits = self._get_expected_ulimits(self.parameters.ulimits)
        self.parameters.expected_etc_hosts = self._convert_simple_dict_to_list('etc_hosts')
        self.parameters.expected_env = self._get_expected_env(image)
        self.parameters.expected_cmd = self._get_expected_cmd()

        self.log("here!!")

        if not self.container.get('HostConfig'):
            self.fail("has_config_diff: Error parsing container properties. HostConfig missing.")
        if not self.container.get('Config'):
            self.fail("has_config_diff: Error parsing container properties. Config missing.")
        if not self.container.get('NetworkSettings'):
            self.fail("has_config_diff: Error parsing container properties. NetworkSettings missing.")

        host_config = self.container['HostConfig']
        log_config = host_config.get('LogConfig', dict())
        restart_policy = host_config.get('RestartPolicy', dict())
        config = self.container['Config']
        network = self.container['NetworkSettings']
        host_config['Ulimits'] = self._get_expected_ulimits(host_config['Ulimits'])

        # The previous version of the docker module ignored the detach state by
        # assuming if the container was running, it must have detached.
        detach = not (config.get('AttachStderr') and config.get('AttachStdout'))

        self.log("command")
        self.log(self.parameters.command, pretty_print=True)
        self.log(self.parameters.expected_ulimits, pretty_print=True)

        # Map parameters to container inspect results
        config_mapping = dict(
            image=config.get('Image'),
            expected_cmd=config.get('Cmd'),
            hostname=config.get('Hostname'),
            user=config.get('User'),
            detach=detach,
            interactive=config.get('OpenStdin'),
            capabilities=host_config.get('CapAdd'),
            devices=host_config.get('Devices'),
            dns_servers=host_config.get('Dns'),
            dns_opts=host_config.get('DnsOptions'),
            dns_search_domains=host_config.get('DnsSearch'),
            expected_env=(config.get('Env') or []),
            expected_entrypoint=host_config.get('Entrypoint'),
            expected_etc_hosts=host_config['ExtraHosts'],
            expected_exposed=[re.sub(r'/.+$', '', p) for p in config.get('ExposedPorts', dict()).keys()],
            groups=host_config.get('GroupAdd'),
            ipc_mode=host_config.get("IpcMode"),
            labels=config.get('Labels'),
            expected_links=host_config.get('Links'),
            log_driver=log_config.get('Type'),
            log_options=log_config.get('Config'),
            mac_address=network.get('MacAddress'),
            memory_swappiness=host_config.get('MemorySwappiness'),
            network_mode=host_config.get('NetworkMode'),
            oom_killer=host_config.get('OomKillDisable'),
            pid_mode=host_config.get('PidMode'),
            privileged=host_config.get('Privileged'),
            expected_ports=host_config.get('PortBindings'),
            read_only=host_config.get('ReadonlyRootfs'),
            restart_policy=restart_policy.get('Name'),
            restart_retries=restart_policy.get('MaximumRetryCount'),
            # Cannot test shm_size, as shm_size is not included in container inspection results.
            # shm_size=host_config.get('ShmSize'),
            security_opts=host_config.get("SecuriytOpt"),
            stop_signal=config.get("StopSignal"),
            tty=config.get('Tty'),
            expected_ulimits=host_config.get('Ulimits'),
            uts=host_config.get('UTSMode'),
            expected_volumes=host_config['Binds'],
            volumes_from=host_config.get('VolumesFrom'),
            volume_driver=host_config.get('VolumeDriver')
        )

        differences = []
        for key, value in config_mapping.iteritems():
            self.log('check differences {0} {1} vs {2}'.format(key, getattr(self.parameters, key), str(value)))
            if getattr(self.parameters, key, None) is not None:
                if isinstance(getattr(self.parameters, key), list) and isinstance(value, list):
                    if len(getattr(self.parameters, key)) > 0 and isinstance(getattr(self.parameters, key)[0], dict):
                        # compare list of dictionaries
                        self.log("comparing list of dict: {0}".format(key))
                        match = self._compare_dictionary_lists(getattr(self.parameters, key), value)
                    else:
                        # compare two lists. Is list_a in list_b?
                        self.log("comparing lists: {0}".format(key))
                        set_a = set(getattr(self.parameters, key))
                        set_b = set(value)
                        match = (set_a <= set_b)
                elif isinstance(getattr(self.parameters, key), dict) and isinstance(value, dict):
                    # compare two dicts
                    self.log("comparing two dicts: {0}".format(key))
                    match = self._compare_dicts(getattr(self.parameters, key), value)
                else:
                    # primitive compare
                    self.log("primitive compare: {0}".format(key))
                    match = (getattr(self.parameters, key) == value)

                if not match:
                    # no match. record the differences
                    item = dict()
                    item[key] = dict(
                        parameter=getattr(self.parameters, key),
                        container=value
                    )
                    differences.append(item)

        has_differences = True if len(differences) > 0 else False
        return has_differences, differences

    def _compare_dictionary_lists(self, list_a, list_b):
        '''
        If all of list_a exists in list_b, return True
        '''
        if not isinstance(list_a, list) or not isinstance(list_b, list):
            return False
        matches = 0
        for dict_a in list_a:
            for dict_b in list_b:
                if self._compare_dicts(dict_a, dict_b):
                    matches += 1
                    break
        result = (matches == len(list_a))
        return result

    def _compare_dicts(self, dict_a, dict_b):
        '''
        If dict_a in dict_b, return True
        '''
        if not isinstance(dict_a, dict) or not isinstance(dict_b, dict):
            return False
        for key, value in dict_a.iteritems():
            if isinstance(value, dict):
                match = self._compare_dicts(value, dict_b.get(key))
            elif isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], dict):
                    match = self._compare_dictionary_lists(value, dict_b.get(key))
                else:
                    set_a = set(value)
                    set_b = set(dict_b.get(key))
                    match = (set_a == set_b)
            else:
                match = (value == dict_b.get(key))
            if not match:
                return False
        return True

    def has_different_resource_limits(self):
        '''
        Diff parameters and container resource limits
        '''
        if not self.container.get('HostConfig'):
            self.fail("limits_differ_from_container: Error parsing container properties. HostConfig missing.")

        host_config = self.container['HostConfig']

        config_mapping = dict(
            cpu_period=host_config.get('CpuPeriod'),
            cpu_quota=host_config.get('CpuQuota'),
            cpuset_cpus=host_config.get('CpusetCpus'),
            cpuset_mems=host_config.get('CpusetMems'),
            cpu_shares=host_config.get('CpuShares'),
            kernel_memory=host_config.get("KernelMemory"),
            memory=host_config.get('Memory'),
            memory_reservation=host_config.get('MemoryReservation'),
            memory_swap=host_config.get('MemorySwap'),
        )

        differences = []
        for key, value in config_mapping.iteritems():
            if getattr(self.parameters, key, None) and getattr(self.parameters, key) != value:
                # no match. record the differences
                item = dict()
                item[key] = dict(
                    parameter=getattr(self.parameters, key),
                    container=value
                )
                differences.append(item)
        different = (len(differences) > 0)
        return different, differences

    def has_missing_networks(self):
        '''
        Check if the container is connected to requested networks
        '''
        missing_networks = []
        missing = False

        if not self.parameters.networks:
            return missing, missing_networks

        if not self.container.get('NetworkSettings'):
            self.fail("has_missing_networks: Error parsing container properties. NetworkSettings missing.")

        connected_networks = self.container['NetworkSettings']['Networks']
        for network, config in self.parameters.networks.iteritems():
            if connected_networks.get(network, None) is None:
                missing_networks.append(network)
        if len(missing_networks) > 0:
            missing = True
        return missing, missing_networks

    def has_extra_networks(self):
        '''
        Check if the container is connected to non-requested networks
        '''
        extra_networks = []
        extra = False

        if not self.parameters.networks:
            return extra, extra_networks

        if not self.container.get('NetworkSettings'):
            self.fail("has_extra_networks: Error parsing container properties. NetworkSettings missing.")

        connected_networks = self.container['NetworkSettings']['Networks']
        for network in connected_networks:
            if network not in ('bridge', 'host') and not network.startswith('container:'):
                if network not in self.parameters.networks:
                    extra_networks.append(network)
        if len(extra_networks) > 0:
            extra = True
        return extra, extra_networks

    def _get_expected_entrypoint(self, image):
        self.log('_get_expected_entrypoint')
        entrypoint = (self.parameters.entrypoint)
        if image and image['ContainerConfig'].get('Entrypoint'):
            entrypoint = list(set(entrypoint + image['ContainerConfig'].get('Entrypoint')))
        return entrypoint

    def _get_expected_ports(self):
        if self.parameters.published_ports is None:
            return None
        expected_bound_ports = {}
        for container_port, config in self.parameters.published_ports.iteritems():
            if isinstance(container_port, int):
                container_port = "{0}/tcp".format(container_port)
            if len(config) == 1:
                expected_bound_ports[container_port] = [{'HostIp': "0.0.0.0", 'HostPort': ""}]
            elif isinstance(config[0], tuple):
                expected_bound_ports[container_port] = []
                for host_ip, host_port in config.iteritems():
                    expected_bound_ports[container_port].append({ 'HostIp': host_ip, 'HostPort': str(host_port)})
            else:
                expected_bound_ports[container_port] = [{'HostIp': config[0], 'HostPort': str(config[1])}]
        return expected_bound_ports

    def _get_expected_links(self):
        if self.parameters.links is None:
            return None
        self.log('parameter links:')
        self.log(self.parameters.links, pretty_print=True)
        exp_links = []
        for link, alias in self.parameters.links.iteritems():
            exp_links.append("/{0}:{1}/{2}".format(link, ('/' + self.parameters.name), alias))
        return exp_links

    def _get_expected_volumes(self, image):
        self.log('_get_expected_volumes')
        image_vols = []
        if image:
            image_vols = self._get_volumes_from_binds(image['ContainerConfig'].get('Volumes'))
        param_vols = []
        if self.parameters.volumes:
            for vol in self.parameters.volumes:
                if len(vol.split(':')) == 3:
                    host, container, mode = vol.split(':')
                else:
                    host, container, mode = vol.split(':') + ['rw']
                # flip to container first
                param_vols.append("{0}:{1}:{2}".format(host, container, mode))
        return list(set(image_vols + param_vols))

    def _get_volumes_from_binds(self, volumes):
        '''
        Convert array of binds to array of strings with format host_path:container_path:mode

        :param volumes: array of bind dicts
        :return: array of strings
        '''
        results = []
        if isinstance(volumes, dict):
            results += self._get_volume_from_dict(volumes)
        elif isinstance(volumes, list):
            for vol in volumes:
                results += self._get_volume_from_dict(vol)
        return results

    def _get_volume_from_dict(self, volume_dict):
        results = []
        if volume_dict:
            for host_path, config in volume_dict.items():
                if isinstance(config, dict) and config.get('bind'):
                    container_path = config.get('bind')
                    mode = config.get('mode', 'rw')
                    results.append("{0}:{1}:{2}".format(host_path, container_path, mode))
        return results

    def _get_expected_env(self, image):
        self.log('_get_expected_env')
        param_env = (self._convert_simple_dict_to_list('env', '=') or [])
        if image and image['ContainerConfig'].get('Env'):
            image_env = image['ContainerConfig'].get('Env')
            param_env = list(set(param_env + image_env))
        return param_env

    def _get_expected_exposed(self, image):
        self.log('_get_expected_exposed')
        image_ports = []
        if image:
            image_ports = [re.sub(r'/.+$', '', p) for p in (image['ContainerConfig'].get('ExposedPorts') or {}).keys()]
        param_ports = (self.parameters.exposed_ports or [])
        if not isinstance(param_ports, list):
            param_ports = [param_ports]
        return list(set(image_ports + param_ports))

    def _get_expected_ulimits(self, config_ulimits):
        self.log('_get_expected_ulimits')
        if config_ulimits is None:
            return None

        results = []
        if isinstance(config_ulimits[0], Ulimit):
            for limit in config_ulimits:
                if limit.hard:
                    results.append("{0}:{1}".format(limit.name, limit.soft, limit.hard))
                else:
                    results.append("{0}:{1}".format(limit.name, limit.soft))
        else:
            for limit in config_ulimits:
                if limit.get('hard'):
                    results.append("{0}:{1}".format(limit.get('name'), limit.get('soft'), limit.get('hard')))
                else:
                    results.append("{0}:{1}".format(limit.get('name'), limit.get('soft')))
        return results

    def _get_expected_cmd(self):
        self.log('_get_expected_cmd')
        if not self.parameters.command:
            return None
        expected_commands = []
        commands = self.parameters.command
        if not isinstance(commands, list):
            commands = [commands]
        for cmd in commands:
            self.log(cmd)
            expected_commands = expected_commands + shlex.split(cmd)
        return expected_commands

    def _convert_simple_dict_to_list(self, param_name, join_with=':'):
        if getattr(self.parameters, param_name, None) is None:
            return None
        results = []
        for key, value in getattr(self.parameters, param_name).iteritems():
            results.append("{0}{1}{2}".format(key, join_with, value))
        return results


class ContainerManager(DockerBaseClass):
    '''
    Perform container management tasks
    '''

    def __init__(self, client, results):

        super(ContainerManager, self).__init__()

        self.client = client
        self.results = results
        self.parameters = TaskParameters(client)
        self.check_mode = self.client.check_mode

        state = self.parameters.state
        if state in ('started', 'present'):
            self.present(state)
        elif state == 'absent':
            self.absent()

    def present(self, state):
        container = self._get_container(self.parameters.name)
        image = self._get_image()

        if not container.found:
            self.log('No container found')
            # New container
            new_container = self.container_create(self.parameters.create_parameters)
            if new_container:
                container = new_container
            container = self.update_limits(container)
            container = self.update_networks(container)
            if state == 'started':
                container = self.container_start(container.Id)
            self.results['results'] = container.raw
            return True

        # Existing container
        self.log(container.raw, pretty_print=True)
        different, differences = container.has_different_configuration(image)
        image_different = self._image_is_different(image, container)
        if image_different:
            self.results['image_different'] = True
        if image_different or different or self.parameters.recreate:
            self.results['config_differences'] = differences
            self.container_stop(container.Id)
            self.container_remove(container.Id)
            new_container = self.container_create(self.parameters.create_parameters)
            if new_container:
                container = new_container

        container = self.update_limits(container)
        container = self.update_networks(container)

        # TODO implement has_extra_networks

        if state == 'started' and not container.running:
            container = self.container_start(container.Id)
        elif state == 'started' and self.parameters.restart:
            self.container_stop(container.Id)
            container = self.container_start(container.Id)
        elif state == 'present' and container.running:
            self.container_stop(container.Id)
            container = self._get_container(container.Id)

        self.results['results'] = container.raw

    def absent(self):
        container = Container(self.client.get_container(self.parameters.name), self.parameters)
        if container.found:
            # TODO if running stop/kill
            self.container_remove(container.Id)

    def fail(self, msg):
        self.client.module.fail_json(msg=msg)

    def _get_container(self, container):
        '''
        Expects container ID or Name. Returns a container object
        '''
        return Container(self.client.get_container(container), self.parameters)

    def _get_image(self):
        if not self.parameters.image:
            self.log('No image specified')
            return None
        repository, tag = utils.parse_repository_tag(self.parameters.image)
        if not tag:
            tag = "latest"
        image = self.client.find_image(repository, tag)
        if not self.check_mode:
            if not image or self.parameters.pull:
                self.log("Pull the image.")
                image = self.client.pull_image(repository, tag)
                self.results['actions'].append(dict(pulled_image="{0}:{1}".format(repository, tag)))
                self.results['changed'] = True
        self.log("image")
        self.log(image, pretty_print=True)
        return image

    def _image_is_different(self, image, container):
        if image and image.get('Id'):
            if container and container.Image:
                if image.get('Id') != container.Image:
                    return True
        return False

    def update_limits(self, container):
        limits_differ, different_limits = container.has_different_resource_limits()
        if limits_differ:
            self.log("limit differences:")
            self.log(different_limits, pretty_print=True)
        if limits_differ and not self.check_mode:
            self.container_update(container.Id, self.parameters.update_parameters)
            return self._get_container(container.Id)
        return container

    def update_networks(self, container):
        networks_missing, missing_networks = container.has_missing_networks()
        if networks_missing:
            self.log("networks missing")
            self.log(missing_networks, pretty_print=True)
        if networks_missing and not self.check_mode:
            for network in missing_networks:
                self.connect_container_to_network(container.Id, network)
            return self._get_container(container.Id)
        return container

    def container_create(self, create_parameters):
        self.log("create container")
        self.log(create_parameters, pretty_print=True)
        if not self.check_mode:
            try:
                new_container = self.client.create_container(**create_parameters)
                self.results['actions'].append(dict(created=new_container.get('Id'),
                                                    create_parameters=create_parameters))
                self.results['changed'] = True
                return self._get_container(new_container['Id'])
            except Exception, exc:
                self.fail("Error creating container: {0}".format(str(exc)))

    def container_start(self, container_id):
        self.log("start container {0}".format(container_id))
        if not self.check_mode:
            try:
                self.client.start(container=container_id)
                self.results['actions'].append(dict(started=container_id))
                self.results['changed'] = True
            except Exception, exc:
                self.fail("Error starting container {0}: {1}".format(container_id, str(exc)))
        return self._get_container(container_id)

    def container_remove(self, container_id, v=False, link=False, force=False):
        self.log("remove container container:{0} v:{1} link:{1} force{2}".format(container_id, v, link, force))
        if not self.check_mode:
            volume_state = (True if self.parameters.keep_volumes else False)
            try:
                response = self.client.remove_container(container_id, v=volume_state, link=link, force=force)
                self.results['actions'].append(dict(removed=container_id, volume_state=volume_state))
                self.results['changed'] = True
                return response
            except Exception, exc:
                self.fail("Error removing container {0}: {1}".format(container_id, str(exc)))

    def container_update(self, container_id, update_parameters):
        if update_parameters:
            self.log("update container {0}".format(container_id))
            self.log(update_parameters, pretty_print=True)
            if not self.check_mode and callable(getattr(self.client, 'update_container')):
                try:
                    self.client.update_container(container_id, **update_parameters)
                    self.results['actions'].append(dict(updated=container_id, update_parameters=update_parameters))
                    self.results['changed'] = True
                except Exception, exc:
                    self.fail("Error updating container {0}: {1}".format(container_id, str(exc)))
        return self._get_container(container_id)

    def container_kill(self, container_id):
        if not self.check_mode:
            try:
                if self.parameters.kill_signal:
                    response = self.client.kill(container_id, signal=self.parameters.kill_signal)
                else:
                    response = self.client.kill(container_id)
                self.results['actions'].append(dict(killed=container_id, signal=self.parameters.kill_signal))
                self.results['changed'] = True
                return response
            except Exception, exc:
                self.fail("Error killing container {0}: {1}".format(container_id, exc))

    def container_stop(self, container_id):
        if self.parameters.force_kill:
            self.container_kill(container_id)
            return

        if not self.check_mode:
            try:
                if self.parameters.stop_timeout:
                    response = self.client.stop(container_id, timeout=self.parameters.stop_timeout)
                else:
                    response = self.client.stop(container_id)
                self.results['actions'].append(dict(stopped=container_id, timeout=self.parameters.stop_timeout))
                self.results['changed'] = True
                return response
            except Exception, exc:
                self.fail("Error stopping container {0}: {1}".format(container_id, str(exc)))

    def connect_container_to_network(self, container_id, network    ):
        pass


def main():
    argument_spec = dict(
        blkio_weight=dict(type='int'),
        capabilities=dict(type='list'),
        command=dict(type='list'),
        cpu_period=dict(type='int'),
        cpu_quota=dict(type='int'),
        cpuset_cpus=dict(type='str'),
        cpuset_mems=dict(type='str'),
        cpu_shares=dict(type='int'),
        detach=dict(type='bool', default=True),
        devices=dict(type='list'),
        dns_servers=dict(type='list'),
        dns_opts=dict(type='list'),
        dns_search_domains=dict(type='list'),
        env=dict(type='dict'),
        entrypoint=dict(type='list'),
        etc_hosts=dict(type='dict'),
        exposed_ports=dict(type='list', aliases=['exposed']),
        force_kill=dict(type='bool', default=False),
        groups=dict(type='list'),
        hostname=dict(type='str'),
        image=dict(type='str'),
        interactive=dict(type='bool', default=False),
        ipc_mode=dict(type='str'),
        keep_volumes=dict(type='bool', default=True),
        kernel_memory=dict(type='str'),
        kill_signal=dict(type='str'),
        labels=dict(type='dict'),
        links=dict(type='list'),
        log_driver=dict(type='str', choices=['json-file', 'syslog', 'journald', 'gelf', 'fluentd',
                                             'awslogs', 'splunk'], default='json-file'),
        log_options=dict(type='str'),
        mac_address=dict(type='str'),
        memory=dict(type='str'),
        memory_reservation=dict(type='str'),
        memory_swap=dict(type='str'),
        memory_swappiness=dict(type='int'),
        name=dict(type='str', required=True),
        network_mode=dict(type='str'),
        networks=dict(type='dict'),
        oom_killer=dict(type='bool'),
        paused=dict(type='bool', default=False),
        pid_mode=dict(type='str', default='host'),
        privileged=dict(type='bool', default=False),
        published_ports=dict(type='list', aliases=['ports']),
        pull=dict(type='bool', default=False),
        read_only=dict(type='bool', default=False),
        recreate=dict(type='bool', default=False),
        restart=dict(type='bool', default=False),
        restart_policy=dict(type='str', choices=['on-failure', 'always']),
        restart_retries=dict(type='int', default=0),
        shm_size=dict(type='str'),
        security_opts=dict(type=list),
        state=dict(type='str', choices=['absent', 'present', 'started', 'stopped'], default='started'),
        stop_signal=dict(type='str'),
        stop_timeout=dict(type='int'),
        trust_image_content=dict(type='bool', default=False),
        tty=dict(type='bool', default=False),
        ulimits=dict(type='list'),
        user=dict(type='str'),
        uts=dict(type='str'),
        volumes=dict(type='list'),
        volumes_from=dict(type='list'),
        volume_driver=dict(type='str'),
    )

    required_if = [
        ('state', 'present', ['image'])
    ]

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True
    )

    results = dict(
        changed=False,
        check_mode=client.check_mode,
        actions=[],
        results={}
    )

    ContainerManager(client, results)
    client.module.exit_json(**results)


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
