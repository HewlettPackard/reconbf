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


def _conf_location():
    return {'dir': '/etc/cinder'}


def _conf_details():
    config = _conf_location().copy()
    config['user'] = 'root'
    config['group'] = 'cinder'
    return config


@test_class.explanation("""
    Protection name: Config permissions

    Check: Are cinder config permissions ok

    Purpose: Cinder config files contain authentication
    details and need to be protected. Ensure that
    they're only available to the service.
    """)
@test_class.set_mapping("OpenStack:Check-Block-01",
                        "OpenStack:Check-Block-02")
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
    files = ['/etc/cinder/cinder.conf',
             '/etc/cinder/api-paste.ini',
             '/etc/cinder/policy.json',
             '/etc/cinder/rootwrap.conf',
             ]
    for f in files:
        path = os.path.join(config['dir'], f)
        result.add_result(path,
                          utils.validate_permissions(path, 0o640, user.pw_uid,
                                                     group.gr_gid))
    return result


@test_class.explanation("""
    Protection name: Authentication strategy

    Check: Make sure proper authentication is used

    Purpose: There are multiple authentication backends
    available. Cinder should be configured to authenticate
    against keystone rather than test backends.
    """)
@test_class.set_mapping("OpenStack:Check-Block-03")
@test_class.takes_config(_conf_location)
def cinder_auth(config):
    try:
        path = os.path.join(config['dir'], 'cinder.conf')
        cinder_conf = utils.parse_openstack_ini(path)
    except EnvironmentError:
        return TestResult(Result.SKIP, 'cannot read cinder config files')

    auth = cinder_conf.get('DEFAULT', {}).get('auth_strategy', 'keystone')
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
@test_class.set_mapping("OpenStack:Check-Block-04")
@test_class.takes_config(_conf_location)
def keystone_secure(config):
    try:
        path = os.path.join(config['dir'], 'cinder.conf')
        cinder_conf = utils.parse_openstack_ini(path)
    except EnvironmentError:
        return TestResult(Result.SKIP, 'cannot read cinder config files')

    protocol = cinder_conf.get('keystone_authtoken', {}).get('auth_protocol',
                                                             'https')
    identity = cinder_conf.get('keystone_authtoken', {}).get('identity_uri',
                                                             'https:')

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
@test_class.set_mapping("OpenStack:Check-Block-05")
@test_class.takes_config(_conf_location)
def nova_secure(config):
    try:
        path = os.path.join(config['dir'], 'cinder.conf')
        cinder_conf = utils.parse_openstack_ini(path)
    except EnvironmentError:
        return TestResult(Result.SKIP, 'cannot read cinder config files')

    insecure = cinder_conf.get('DEFAULT', {}).get(
        'nova_api_insecure', 'False').lower() == 'true'

    if insecure:
        return TestResult(Result.FAIL, 'nova access is not secure')
    else:
        return TestResult(Result.PASS)


@test_class.explanation("""
    Protection name: Glance api access

    Check: Does Glance access use secure connection

    Purpose: OpenStack components communicate with each other
    using various protocols and the communication might
    involve sensitive / confidential data.  An attacker may
    try to eavesdrop on the channel in order to get access to
    sensitive information. Thus all the components must
    communicate with each other using a secured communication
    protocol.
    """)
@test_class.set_mapping("OpenStack:Check-Block-06")
@test_class.takes_config(_conf_location)
def glance_secure(config):
    try:
        path = os.path.join(config['dir'], 'cinder.conf')
        cinder_conf = utils.parse_openstack_ini(path)
    except EnvironmentError:
        return TestResult(Result.SKIP, 'cannot read cinder config files')

    insecure = cinder_conf.get('DEFAULT', {}).get(
        'glance_api_insecure', 'False').lower() == 'true'

    if insecure:
        return TestResult(Result.FAIL, 'glance access is not secure')
    else:
        return TestResult(Result.PASS)


@test_class.explanation("""
    Protection name: Strategy for NAS file storage

    Check: Are strict permissions enforced on NAS storage

    Purpose: NAS volume files can be stored either with root
    or non-root ownership and with open or strict permissions.
    Report on both of those settings.
    """)
@test_class.set_mapping("OpenStack:Check-Block-07")
@test_class.takes_config(_conf_location)
def nas_security(config):
    try:
        path = os.path.join(config['dir'], 'cinder.conf')
        cinder_conf = utils.parse_openstack_ini(path)
    except EnvironmentError:
        return TestResult(Result.SKIP, 'cannot read cinder config files')

    secure_operations = cinder_conf.get('DEFAULT', {}).get(
        'nas_secure_file_operations', 'auto').lower() != 'false'
    secure_permissions = cinder_conf.get('DEFAULT', {}).get(
        'nas_secure_file_permissions', 'auto').lower() != 'false'

    results = GroupTestResult()

    if secure_operations:
        results.add_result('operations', TestResult(Result.PASS))
    else:
        results.add_result('operations', TestResult(
            Result.FAIL, 'NAS operations are not secure'))

    if secure_permissions:
        results.add_result('permissions', TestResult(Result.PASS))
    else:
        results.add_result('permissions', TestResult(
            Result.FAIL, 'NAS permissions are not secure'))

    return results


@test_class.explanation("""
    Protection name: Body size limit

    Check: Ensure large requests are stopped.

    Purpose: Large requests can cause a denial of service.
    Setting up a limit ensures that they're rejected without
    full processing.
    """)
@test_class.set_mapping("OpenStack:Check-Block-08")
@test_class.takes_config(_conf_location)
def body_size(config):
    try:
        path = os.path.join(config['dir'], 'cinder.conf')
        cinder_conf = utils.parse_openstack_ini(path)
    except EnvironmentError:
        return TestResult(Result.SKIP, 'cannot read cinder config files')

    osapi_max_body_size = int(cinder_conf.get('DEFAULT', {}).get(
        'osapi_max_request_body_size', '114688'))
    oslo_max_body_size = int(cinder_conf.get('oslo_middleware', {}).get(
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
