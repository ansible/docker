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
        self.enrtypoint = None
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
        self.volume = None
        self.volumes_from = None
        self.volume_driver = None
        self.debug = None
        self.debug_file = None

        for key in client.module_params:
            setattr(self, key, client.module_params[key])

        for param_name in REQUIRES_CONVERSION_TO_BYTES:
            if client.module.params.get(param_name) is not None:
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

        for key, value in client.module.params.iteritems():
            self.log("{0}: {1}".format(key, value))

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
            host_config=self._host_config()
        )
        for key, value in create_params.iteritems():
            if getattr(self, value, None) is not None:
                result[key] = getattr(self, value)
        return result

    def _host_config(self):
        '''
        Returns parameters used to create a HostConfig object
        '''

        host_config_params=dict(
            binds='volumes',
            port_bindings='published_ports',
            publish_all_ports='pubish_all_ports',
            links='links',
            privileged='privileged',
            dns='dns_servers',
            dns_search='dns_search_domains',
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

    def has_different_configuration(self):
        '''
        Diff parameters and existing container config. Returns tuple: (True | False, List of differences)
        '''

        self.parameters.expected_links = self._get_expected_links()
        self.parameters.expected_ports = self._get_expected_ports()
        self.parameters.expected_exposed = self._get_expected_exposed()
        self.parameters.expected_volumes = self._get_expected_volumes()
        self.parameters.expected_ulimits = self._get_expected_ulimits(self.parameters.ulimits)
        self.parameters.expected_etc_hosts = self._convert_simple_dict_to_list('etc_hosts')
        self.parameters.expected_env = self._convert_simple_dict_to_list('env', '=')

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
        detached = (config.get('AttachStderr') and config.get('AttachStdout'))
        host_config['Ulimits'] = self._get_expected_ulimits(host_config['Ulimits'])

        self.log(self.parameters.expected_ulimits, pretty_print=True)

        # Map parameters to container inspect results
        config_mapping = dict(
            image=config.get('Image'),
            command=config.get('Cmd'),
            hostname=config.get('Hostname'),
            user=config.get('User'),
            detaached=detached,
            interactive=config.get('OpenStdin'),
            capabilities=host_config.get('CapAdd'),
            devices=host_config.get('Devices'),
            dns_servers=host_config.get('Dns'),
            dns_opts=host_config.get('DnsOptions'),
            dns_search_domains=host_config.get('DnsSearch'),
            expected_env=config.get('Env'),
            enrtypoint=host_config.get('Entrypoint'),
            expected_etc_hosts=host_config['ExtraHosts'],
            expected_exposed=config.get('ExposedPorts'),
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
            # Cannot test shm_size, as shm_size is not incuded in container inspection results.
            # shm_size=host_config.get('ShmSize'),
            security_opts=host_config.get("SecuriytOpt"),
            stop_signal=config.get("StopSignal"),
            tty=config.get('Tty'),
            expected_ulimits=host_config.get('Ulimits'),
            uts=host_config.get('UTSMode'),
            expected_volumes=config.get('Volumes'),
            volumes_from=host_config.get('VolumesFrom'),
            volume_driver=host_config.get('VolumeDriver')
        )

        differences = []
        for key, value in config_mapping.iteritems():
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
                match = self._compare_dicts(value, dict_b[key])
            elif isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], dict):
                    match = self._compare_dictionary_lists(value, dict_b[key])
                else:
                    set_a = set(value)
                    set_b = set(dict_b[key])
                    match = (set_a == set_b)
            else:
                match = (value == dict_b[key])
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

    def _get_expected_volumes(self):
        if self.parameters.volumes is None:
            return None
        expected_binds = []
        for host_path, config in self.parameters.volumes.iteritems():
            if isinstance(config, dict):
                container_path = config['bind']
                mode = config['mode']
            else:
                container_path = config
                mode = 'rw'
            expected_binds.append("{0}:{1}:{2}".format(host_path, container_path, mode))
        return expected_binds

    def _get_expected_exposed(self):
        if self.parameters.exposed_ports is None:
            return None
        ports = []
        for p in self.parameters.exposed_ports:
            ports.append("/".join(p))
        return ports

    def _get_expected_ulimits(self, config_ulimits):
        if config_ulimits is None:
            return None

        results = []
        if isinstance(config_ulimits, Ulimit):
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

        # TODO - validate that requested image exists. Define and implement actions to take
        #        when the image does not exist.

        if not container.found:
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
        different, differences = container.has_different_configuration()

        if different or self.parameters.recreate:
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
                self.fail("Error creating container {0}: {1}".format(container_id, str(exc)))
        return None

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
        return None

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
        command=dict(type='str'),
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
        enrtypoint=dict(type='list'),
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
        debug_file=dict(type='str', default='docker_container.log')
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    results = dict(
        changed=False,
        check_mode=client.check_mode,
        actions=[],
        results={}
    )

    if client.module.params.get('debug'):
        logging.basicConfig(filename=client.module.params.get('debug_file'), level=logging.DEBUG)

    ContainerManager(client, results)
    client.module.exit_json(**results)


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
