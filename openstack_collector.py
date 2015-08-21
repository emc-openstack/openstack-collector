#!/usr/bin/env python
# Copyright (c) 2015 EMC Corporation, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
This is a tool to collect informations from OpenStack nodes.

Version history:
    0.1.0 - Initial version
"""

import ConfigParser
import logging
import os
import paramiko
import pexpect
import subprocess
import sys
import time

NAME = '__OPENSTACK_COLLECTOR__'
STOR_DIR = '.'

logger = logging.getLogger(NAME)


class RemoteExecutor(object):
    def __init__(self, ip, user, pwd, port=22):
        self.user = user
        self.pwd = pwd
        self.ip = ip
        self.port = port
        self.conn = None

    def connect(self):
        if not self.conn:
            self.conn = paramiko.SSHClient()
            self.conn.set_missing_host_key_policy(
                paramiko.AutoAddPolicy())
            self.conn.connect(
                self.ip, self.port,
                self.user, self.pwd,
                None)
        return

    def execute(self, cmd, sudo=False):
        if sudo:
            cmd = 'echo %s | sudo -S %s' % (self.pwd, cmd)
        stdin, stdout, stderr = self.conn.exec_command(cmd)
        channel = stdout.channel
        out = channel.makefile('rb', -1).readlines()
        if ''.join(out).find('password') >= 0:
            time.sleep(1)
            stdin.write("%s\n" % self.pwd)
            out = channel.makefile('rb', -1).readlines()
        rc = channel.recv_exit_status()
        if not out:
            out = channel.makefile_stderr('rb', -1).readlines()
        if stdin:
            stdin.flush()
            stdin.close()
        if stdout:
            stdout.close()
        if stderr:
            stderr.close()
        return rc, out


class Node(object):
    # Information which we want to get from node.
    # The format is, filename: (command, sudo)
    INFOS = {
        'uname': ('uname -a', False),
        'cpuinfo': ('cat /proc/cpuinfo', False),
        'iscsi_name': ('cat /etc/iscsi/initiatorname.iscsi', True),
        'ip_route': ('ip route', False),
        'meminfo': ('cat /proc/meminfo', False),
        'ip_addr': ('ip addr', False),
        'iscsi_session': ('iscsiadm -m session', False),
        'fc_hba_info': ('systool -c fc_host -v', False),
        'disk_by_path': ('ls -l /dev/disk/by-path', False),
        'multipath_ll': ('multipath -ll', True)
    }

    @classmethod
    def construct_node(cls, conf, sec, host):
        '''Construct a node object from node section in config file'''
        user = conf.get(sec, 'user')
        pwd = conf.get(sec, 'password')
        ip = conf.get(sec, 'ip')
        roles = None
        logdir = None
        confdir = None
        if conf.has_option(sec, 'roles'):
            roles = trim_char(conf.get(sec, 'roles'), ' ').split(',')
        if conf.has_option(sec, 'log_dirs'):
            logdir = trim_char(conf.get(sec, 'log_dirs'), ' ').split(',')
        if conf.has_option(sec, 'conf_dirs'):
            confdir = trim_char(conf.get(sec, 'conf_dirs'), ' ').split(',')
        return Node(user, pwd, roles, ip, True, logdir, confdir, host)

    def __init__(self, user=None, pwd=None, roles=None,
                 ip=None, remote=True, logdir=None,
                 confdir=None, host=None):
        self.ip = ip
        self.user = user
        self.pwd = pwd
        self.roles = roles
        self.remote = remote
        self.info = None
        self.executor = None
        if self.remote:
            self.executor = RemoteExecutor(
                self.ip, self.user, self.pwd)
            logger.info('connecting to %s ..' % self.ip)
            self.executor.connect()
        self.hostname = self.get_host_name()
        self.directory = None
        self.logdir = logdir
        self.confdir = confdir
        self.host = host

    def execute(self, cmd, sudo=False):
        if self.remote:
            out = self.executor.execute(' '.join(cmd), sudo)[1]
            return ' '.join(out)
        else:
            child = subprocess.Popen(
                cmd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False)
            return child.communicate()[0]

    def get_host_name(self):
        return trim_char(self.execute(['hostname']), '\n')

    def gather_node_info(self):
        files = self.INFOS.keys()
        cmds = [self.INFOS[f][0].split(' ') for f in files]
        sudos = [self.INFOS[f][1] for f in files]
        number = len(files)
        contents = map(self.execute, cmds, sudos)
        map(save_to_file, contents, [self.directory] * number, files)
        return

    def mk_node_dir_tree(self, root):
        name = os.path.join(root, self.hostname)
        self.host.execute(['mkdir', '-p', name])
        self.host.execute(['mkdir', '-p', os.path.join(name, 'logs')])
        self.host.execute(['mkdir', '-p', os.path.join(name, 'confs')])
        self.directory = name
        return name

    def mk_dir(self, name):
        name = os.path.join(self.directory, name)
        if not os.path.exists(name):
            self.host.execute(['mkdir', '-p', name])

    def get_logs(self):
        if not self.directory:
            logger.error('No storage directory for this node.')
            return
        logs = None
        if self.logdir:
            logs = self.logdir
        else:
            logs = [os.path.join('/var/log/', role) for role in self.roles]
        if logs:
            for each in logs:
                sub = os.path.join('logs/', os.path.basename(each))
                self.mk_dir(sub)
                Collection(
                    each, '*', os.path.join(self.directory, sub)).collect(self)

    def get_confs(self):
        if not self.directory:
            logger.error('No storage directory for this node.')
            return
        confs = None
        if self.confdir:
            confs = self.confdir
        else:
            confs = [os.path.join('/etc/', role) for role in self.roles]
        if confs:
            for each in confs:
                sub = os.path.join('confs/', os.path.basename(each))
                self.mk_dir(sub)
                Collection(
                    each, '*', os.path.join(self.directory, sub)).collect(self)


class Collection(object):
    def __init__(self, directory=None, filename=None, destination=None):
        self.directory = directory
        self.filename = filename
        self.destination = destination

    def collect(self, src_node):
        src_file = os.path.join(self.directory, self.filename)
        logger.info('collecting %(filename)s from %(host)s ..' %
                    {'filename': src_file,
                     'host': src_node.hostname})
        get_file(
            src_node,
            src_file,
            self.destination)


def save_to_file(content, directory, filename):
    file_path = os.path.join(directory, filename)
    with open(file_path, 'w+') as f:
        f.writelines(content)


def get_file(src_node, src_file, destination):
    src = '%(user)s@%(ip)s:%(file_path)s' % \
          {'user': src_node.user,
           'ip': src_node.ip,
           'file_path': src_file}
    cmd = ['scp', '-r', src, destination]
    prompts = ['continue connecting (yes/no)?', 'password:']
    child = pexpect.spawn(' '.join(cmd))
    p = child.expect(prompts)
    if p == 0:
        child.sendline('yes')
        p = child.expect(prompts)
    if p == 1:
        child.sendline(src_node.pwd)
    time.sleep(0.1)
    child.interact()
    return ''.join(child.readlines())


def trim_char(s, c):
    s = s.replace(c, '')
    return s


def get_current_time():
    return time.strftime('%Y%m%d%H%M%S',
                         time.localtime(time.time()))


def mk_collection_dir(host):
    name = os.path.join(STOR_DIR, 'collection_' + get_current_time())
    host.execute(['mkdir', '-p', name])
    return name


def pack_files(host, destdir):
    basename = os.path.basename(destdir)
    logger.info('Start packaging %s ...' % basename)
    packname = os.path.join(STOR_DIR, basename + '.tar.gz')
    host.execute(['tar', '-zcvf', packname, destdir])
    logger.info('The file %s is available in %s ' % (packname, STOR_DIR))
    return packname


def init_logger(level):
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s')
    hdr = logging.StreamHandler()
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)
    logger.setLevel(level)


def usage():
    print("""
Usage:
    python openstack_collector.py --config-file <file>

Note: This tool intends to collect informations from OpenStack nodes.""")  # noqa


def main():
    '''The main function of this tool'''
    if len(sys.argv) < 3 or sys.argv[1] != '--config-file':
        usage()
        return 1

    # Set log level to debug
    init_logger(logging.DEBUG)

    # If the config file is not specified, return directly
    conf_file = sys.argv[2]
    if not os.path.exists(conf_file):
        logger.error('Can not find the config file: %s' % conf_file)
        return 2

    # Construct node objects
    conf = ConfigParser.ConfigParser()
    conf.read(conf_file)
    host = Node(remote=False)
    nodes = []
    nodes_name = trim_char(conf.get('default', 'nodes'), ' ')
    if conf.has_option('default', 'storage_dir'):
        global STOR_DIR
        STOR_DIR = trim_char(conf.get('default', 'storage_dir'), ' ')
    if nodes_name:
        nodes = [
            Node.construct_node(conf, e, host) for e in nodes_name.split(',')
        ]

    # Create the directory to storage the informations
    root = mk_collection_dir(host)

    # Gathering the information from nodes
    for node in nodes:
        node.mk_node_dir_tree(root)
        logger.info(
            "Start gathering information from node: %s" % node.hostname)
        node.gather_node_info()
        node.get_logs()
        node.get_confs()

    # Packaging the storage directory
    pack_files(host, root)
    host.execute(['rm', '-rf', root])
    return 0

if __name__ == '__main__':
    sys.exit(main())
