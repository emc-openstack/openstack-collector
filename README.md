# OpenStack Information Collect Tool

Copyright (c) 2015 EMC Corporation, Inc.
All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

## Overview

This is a tool to collect information from OpenStack nodes.

## Requirements

To run this tool, two python modules are required:

* paramiko
* pexpect

## What can be collected

* nodes' information: cpu, memory, iscsi, fc, operating system, multipath, network, etc
* OpenStack log files
* OpenStack configuration files

## Usage

        python openstack_collector.py --config-file env.conf

## Configuration

Here is an example of the configuration file:

        # example of openstack collect tool's config file
        [default]
        nodes = node1, node2
        # The default value of storage directory is ./
        #storage_dir = ./

        [node1]
        ip = 192.168.1.181
        user = stack
        password = welcome
        # The roles of the node, currently
        # only support nova and cinder
        roles = nova, cinder
        # The directories of configuration files
        # which you want to collect.
        conf_dirs = /etc/cinder, /etc/nova
        # The directories of log files
        # which you want to collect.
        log_dirs = /var/log/cinder, /var/log/nova

        [node2]
        ip = 192.168.1.182
        user = stack
        password = welcome
        roles = cinder
        conf_dirs = /etc/cinder
        log_dirs = /var/log/cinder

* The user needs to specify the OpenStack nodes by setting `nodes` in the default section.
* The user can specify the location to store the information collected from nodes by setting `storage_dir` in the default section.
* The user needs to configure each node's `ip`, `user`, `password` in the node's section. It is recommended to configure an account with sudo previlege because some commands need sudo previlege. Otherwise, the information which needs sudo previlege can not be collected.
* The user can specify the locations of log and configuration files by setting `log_dirs` and `conf_dirs` in the node's section. If these options are not set, the tool will collect the log and configuration files from `/var/log` and `/etc`.
