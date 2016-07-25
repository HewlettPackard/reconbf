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


# While this doesn't take the openstack config types into account, this should
# be good enough. Lists can be parsed as needed and multi-values can be
# special-cased.
def _parse_openstack_ini_contents(fobj):
    section = 'DEFAULT'
    config = collections.defaultdict(dict)

    for line in fobj:
        line = line.strip()
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


@test_class.explanation("""
    Protection name: No admin token

    Check: Ensure no admin token is configured for keystone
    authentication.

    Purpose: Admin token should only be used for initial
    configuration. Once the system is running, the token
    should be removed and only runtime configuration used.
    """)
@test_class.set_mapping("OpenStack:Check-Identity-06")
def admin_token():
    try:
        keystone_ini = _parse_openstack_ini('/etc/keystone/keystone.conf')
        paste_ini = _parse_openstack_ini('/etc/keystone/keystone-paste.ini')
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
def body_size():
    try:
        keystone_ini = _parse_openstack_ini('/etc/keystone/keystone.conf')
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
def token_hash():
    try:
        keystone_ini = _parse_openstack_ini('/etc/keystone/keystone.conf')
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
