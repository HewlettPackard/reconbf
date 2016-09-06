# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from reconbf.lib import test_class
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult
from reconbf.lib import utils
import grp
import os
import pwd
import functools


def _conf_location():
    return {'dir': '/etc/neutron'}


def _conf_details():
    config = _conf_location().copy()
    config['user'] = 'root'
    config['group'] = 'neutron'
    return config


@test_class.explanation("""
    Protection name: Config permissions

    Check: Are manila config permissions ok

    Purpose: Manila config files contain authentication
    details and need to be protected. Ensure that
    they're only available to the service.
    """)
@test_class.set_mapping("OpenStack:Check-Neutron-01",
                        "OpenStack:Check-Neutron-02")
@test_class.takes_config(_conf_details)
def config_permission(config):
    try:
        user = pwd.getpwnam(config['user'])
    except KeyError:
        return TestResult(Result.SKIP,
                          'Could not find user "%s"' % config['user'])

    try:
        group = grp.getgrnam(config['group'])
    except KeyError:
        return TestResult(Result.SKIP,
                          'Could not find group "%s"' % config['group'])

    result = GroupTestResult()
    files = ['neutron.conf', 'api-paste.ini', 'policy.json', 'rootwrap.conf']
    for f in files:
        path = os.path.join(config['dir'], f)
        result.add_result(path,
                          utils.validate_permissions(path, 0o640, user.pw_uid,
                                                     group.gr_gid))
    return result


def _checks_config(f):
    @functools.wraps(f)
    def wrapper(config):
        try:
            path = os.path.join(config['dir'], 'neutron.conf')
            conf = utils.parse_openstack_ini(path)
        except EnvironmentError:
            return TestResult(Result.SKIP, 'cannot read neutron config file')
        return f(conf)
    return wrapper


@test_class.explanation("""
    Protection name: Authentication strategy

    Check: Make sure proper authentication is used

    Purpose: There are multiple authentication backends
    available. Neutron should be configured to authenticate
    against keystone rather than test backends.
    """)
@test_class.set_mapping("OpenStack:Check-Neutron-03")
@test_class.takes_config(_conf_location)
@_checks_config
def auth(conf):
    auth = conf.get('DEFAULT', {}).get('auth_strategy', 'keystone')
    if auth != 'keystone':
        return TestResult(Result.FAIL,
                          'authentication should be done by keystone')
    else:
        return TestResult(Result.PASS)


@test_class.explanation("""
    Protection name: Keystone api access

    Check: Does Keystone access use secure connection

    Purpose: OpenStack components communicate with each other
    using various protocols and the communication might
    involve sensitive / confidential data.  An attacker may
    try to eavesdrop on the channel in order to get access to
    sensitive information. Thus all the components must
    communicate with each other using a secured communication
    protocol.
    """)
@test_class.set_mapping("OpenStack:Check-Neutron-04")
@test_class.takes_config(_conf_location)
@_checks_config
def keystone_secure(conf):
    protocol = conf.get('keystone_authtoken', {}).get('auth_protocol', 'https')
    identity = conf.get('keystone_authtoken', {}).get('identity_uri', 'https:')

    if not identity.startswith('https:'):
        return TestResult(Result.FAIL, 'keystone access is not secure')
    if protocol != 'https':
        return TestResult(Result.FAIL, 'keystone access is not secure')

    return TestResult(Result.PASS)


@test_class.explanation("""
    Protection name: Secure API access

    Check: Does Neutron API expect SSL connections

    Purpose: Neutron requests include sensitive information.
    Using encrypted channel prevents exposing it to anyone
    capturing the traffic.
    """)
@test_class.set_mapping("OpenStack:Check-Neutron-05")
@test_class.takes_config(_conf_location)
@_checks_config
def use_ssl(conf):
    ssl = conf.get('DEFAULT', {}).get('use_ssl', 'False')
    ssl = ssl.lower() == 'true'

    if ssl:
        return TestResult(Result.PASS)
    else:
        return TestResult(Result.FAIL, 'SSL not used for the neutron API')
