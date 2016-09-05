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
    return {'dir': '/etc/manila'}


def _conf_details():
    config = _conf_location().copy()
    config['user'] = 'root'
    config['group'] = 'manila'
    return config


@test_class.explanation("""
    Protection name: Config permissions

    Check: Are manila config permissions ok

    Purpose: Manila config files contain authentication
    details and need to be protected. Ensure that
    they're only available to the service.
    """)
@test_class.set_mapping("OpenStack:Check-Shared-01",
                        "OpenStack:Check-Shared-02")
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
    files = ['manila.conf', 'api-paste.ini', 'policy.json', 'rootwrap.conf']
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
            path = os.path.join(config['dir'], 'manila.conf')
            conf = utils.parse_openstack_ini(path)
        except EnvironmentError:
            return TestResult(Result.SKIP, 'cannot read manila config file')
        return f(conf)
    return wrapper


@test_class.explanation("""
    Protection name: Authentication strategy

    Check: Make sure proper authentication is used

    Purpose: There are multiple authentication backends
    available. Manila should be configured to authenticate
    against keystone rather than test backends.
    """)
@test_class.set_mapping("OpenStack:Check-Shared-03")
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
@test_class.set_mapping("OpenStack:Check-Shared-04")
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
    Protection name: Nova api access

    Check: Does Nova access use secure connection

    Purpose: OpenStack components communicate with each other
    using various protocols and the communication might
    involve sensitive / confidential data.  An attacker may
    try to eavesdrop on the channel in order to get access to
    sensitive information. Thus all the components must
    communicate with each other using a secured communication
    protocol.
    """)
@test_class.set_mapping("OpenStack:Check-Shared-05")
@test_class.takes_config(_conf_location)
@_checks_config
def nova_secure(conf):
    insecure = conf.get('DEFAULT', {}).get('nova_api_insecure', 'false')
    insecure = insecure.lower() == 'true'

    if insecure:
        return TestResult(Result.FAIL, 'nova access is not secure')
    else:
        return TestResult(Result.PASS)


@test_class.explanation("""
    Protection name: Neutron api access

    Check: Does Neutron access use secure connection

    Purpose: OpenStack components communicate with each other
    using various protocols and the communication might
    involve sensitive / confidential data.  An attacker may
    try to eavesdrop on the channel in order to get access to
    sensitive information. Thus all the components must
    communicate with each other using a secured communication
    protocol.
    """)
@test_class.set_mapping("OpenStack:Check-Shared-06")
@test_class.takes_config(_conf_location)
@_checks_config
def neutron_secure(conf):
    insecure = conf.get('DEFAULT', {}).get('neutron_api_insecure', 'false')
    insecure = insecure.lower() == 'true'

    if insecure:
        return TestResult(Result.FAIL, 'neutron access is not secure')
    else:
        return TestResult(Result.PASS)


@test_class.explanation("""
    Protection name: Cinder api access

    Check: Does Cinder access use secure connection

    Purpose: OpenStack components communicate with each other
    using various protocols and the communication might
    involve sensitive / confidential data.  An attacker may
    try to eavesdrop on the channel in order to get access to
    sensitive information. Thus all the components must
    communicate with each other using a secured communication
    protocol.
    """)
@test_class.set_mapping("OpenStack:Check-Shared-07")
@test_class.takes_config(_conf_location)
@_checks_config
def cinder_secure(conf):
    insecure = conf.get('DEFAULT', {}).get('cinder_api_insecure', 'false')
    insecure = insecure.lower() == 'true'

    if insecure:
        return TestResult(Result.FAIL, 'cinder access is not secure')
    else:
        return TestResult(Result.PASS)


@test_class.explanation("""
    Protection name: Body size limit

    Check: Ensure large requests are stopped.

    Purpose: Large requests can cause a denial of service.
    Setting up a limit ensures that they're rejected without
    full processing.
    """)
@test_class.set_mapping("OpenStack:Check-Shared-08")
@test_class.takes_config(_conf_location)
@_checks_config
def body_size(conf):
    osapi_max_body_size = int(conf.get('DEFAULT', {}).get(
        'osapi_max_request_body_size', '114688'))
    oslo_max_body_size = int(conf.get('oslo_middleware', {}).get(
        'max_request_body_size', '114688'))

    results = GroupTestResult()

    res_name = 'osapi body size'
    if osapi_max_body_size <= 114688:
        results.add_result(res_name, TestResult(Result.PASS))
    else:
        results.add_result(res_name, TestResult(
            Result.FAIL, 'osapi allows too big request bodies'))

    res_name = 'oslo body size'
    if oslo_max_body_size <= 114688:
        results.add_result(res_name, TestResult(Result.PASS))
    else:
        results.add_result(res_name, TestResult(
            Result.FAIL, 'middleware allows too big request bodies'))

    return results
