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

from reconbf.lib.logger import logger
from reconbf.lib import test_class
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult
from reconbf.lib import utils
import collections
import grp
import os
import pwd


# While this doesn't take the openstack config types into account, this should
# be good enough. Lists can be parsed as needed and multi-values can be
# special-cased.
def _parse_openstack_ini_contents(fobj):
    section = 'DEFAULT'
    config = collections.defaultdict(dict)

    for line in fobj:
        line = line.strip()
        if not line:
            continue

        if line.startswith('#'):
            continue

        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            continue

        parts = line.split('=', 1)
        if len(parts) != 2:
            logger.warning("line cannot be parsed: '%s'", line)
            continue

        key, value = parts
        key = key.strip()
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]

        config[section][key] = value

    return config


@utils.idempotent
def _parse_openstack_ini(path):
    with open(path, 'r') as f:
        contents = _parse_openstack_ini_contents(f)
    return contents


def _conf_location():
    return {'dir': '/etc/keystone'}


@test_class.explanation("""
    Protection name: No admin token

    Check: Ensure no admin token is configured for keystone
    authentication.

    Purpose: Admin token should only be used for initial
    configuration. Once the system is running, the token
    should be removed and only runtime configuration used.
    """)
@test_class.set_mapping("OpenStack:Check-Identity-06")
@test_class.takes_config(_conf_location)
def admin_token(config):
    try:
        path = os.path.join(config['dir'], 'keystone.conf')
        keystone_ini = _parse_openstack_ini(path)
        path = os.path.join(config['dir'], 'keystone-paste.ini')
        paste_ini = _parse_openstack_ini(path)
    except EnvironmentError:
        return TestResult(Result.SKIP, 'cannot read keystone config files')

    keystone_req = {
        "DEFAULT.admin_token": {"disallowed": "*"},
    }
    keystone_res = utils.verify_config("keystone.conf", keystone_ini,
                                       keystone_req, needs_parsing=False)

    paste_req = {
        "filter:admin_token_auth.AdminTokenAuthMiddleware": {"disallowed": "*"}
    }
    paste_res = utils.verify_config("keystone-paste.ini", paste_ini, paste_req,
                                    needs_parsing=False)

    result = GroupTestResult()
    for res in keystone_res:
        result.add_result(res[0], res[1])
    for res in paste_res:
        result.add_result(res[0], res[1])
    return result


@test_class.explanation("""
    Protection name: Body size limit

    Check: Ensure large requests are stopped.

    Purpose: Large requests can cause a denial of service.
    Setting up a limit ensures that they're rejected without
    full processing.
    """)
@test_class.set_mapping("OpenStack:Check-Identity-05")
@test_class.takes_config(_conf_location)
def body_size(config):
    try:
        path = os.path.join(config['dir'], 'keystone.conf')
        keystone_ini = _parse_openstack_ini(path)
    except EnvironmentError:
        return TestResult(Result.SKIP, 'cannot read keystone config files')

    keystone_req = {
        "DEFAULT.max_request_body_size": {"allowed": "*"},
    }
    keystone_res = utils.verify_config("keystone.conf", keystone_ini,
                                       keystone_req, needs_parsing=False)

    result = GroupTestResult()
    for res in keystone_res:
        result.add_result(res[0], res[1])
    return result


@test_class.explanation("""
    Protection name: Token hash algorithm

    Check: Verify whether pki tokens are used with weak
    hashes.

    Purpose: If the token provider is either pki or pkiz
    make sure that a strong hash is used, preventing
    spoofing of credentials.
    """)
@test_class.set_mapping("OpenStack:Check-Identity-04")
@test_class.takes_config(_conf_location)
def token_hash(config):
    try:
        path = os.path.join(config['dir'], 'keystone.conf')
        keystone_ini = _parse_openstack_ini(path)
    except EnvironmentError:
        return TestResult(Result.SKIP, 'cannot read keystone config files')

    provider = keystone_ini.get('token', {}).get('provider', 'uuid')
    if (provider.startswith('keystone.token.providers.') and
            provider.endswith('.Provider')):
        provider = provider[25:-9]

    if provider not in ('pki', 'pkiz'):
        return TestResult(Result.SKIP, 'test relevant only for pki tokens')

    single = keystone_ini.get('token', {}).get('hash_algorithm')
    plural = keystone_ini.get('token', {}).get('hash_algorithms')
    val = plural or single

    if val is None or val.lower() not in ('sha256', 'sha512'):
        return TestResult(Result.FAIL, 'token hash should be sha256 or sha512')

    return TestResult(Result.PASS)


def _conf_details():
    config = _conf_location().copy()
    config['user'] = 'keystone'
    config['group'] = 'keystone'
    return config


@test_class.explanation("""
    Protection name: Config permissions

    Check: Are keystone config permissions ok

    Purpose: Keystone config files are critical to the
    system's authentication. Ensure that they're only
    available to the service.
    """)
@test_class.set_mapping("OpenStack:Check-Identity-01",
                        "OpenStack:Check-Identity-02")
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

    def _check_ownership(path):
        try:
            st = os.stat(path)
        except EnvironmentError:
            return TestResult(Result.SKIP, 'file %s not found' % path)

        if st.st_uid != user.pw_uid:
            return TestResult(Result.FAIL,
                              'Unexpected owner uid %s' % st.st_uid)
        if st.st_gid != group.gr_gid:
            return TestResult(Result.FAIL,
                              'Unexpected group gid %s' % st.st_gid)
        if st.st_mode & 0o640 != st.st_mode & 0o666:
            return TestResult(Result.FAIL,
                              'Permissions on the file should be more strict')
        return TestResult(Result.PASS)

    result = GroupTestResult()
    files = ['keystone.conf',
             'keystone-paste.ini',
             'policy.json',
             'logging.conf',
             'ssl/certs/signing_cert.pem',
             'ssl/private/signing_key.pem',
             'ssl/certs/ca.pem',
             ]
    for f in files:
        path = os.path.join(config['dir'], f)
        result.add_result(path, _check_ownership(path))
    return result
