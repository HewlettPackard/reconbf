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
from reconbf.lib.logger import logger
import grp
import os
import pwd
import ast
import functools


class NotConstant(Exception):
    pass


if hasattr(ast, 'Bytes'):
    # py3
    str_types = (ast.Str, ast.Bytes)
else:
    # py2
    str_types = (ast.Str,)


def _resolve_constant(node):
    if isinstance(node, str_types):
        return node.s
    elif isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.List):
        return [_resolve_constant(e) for e in node.elts]
    elif isinstance(node, ast.Set):
        return set(_resolve_constant(e) for e in node.elts)
    elif isinstance(node, ast.Tuple):
        return tuple(_resolve_constant(e) for e in node.elts)
    elif isinstance(node, ast.Dict):
        res = {}
        for k, v in zip(node.keys, node.values):
            res[_resolve_constant(k)] = _resolve_constant(v)
        return res
    else:
        raise NotConstant()


# This parses .py files for simple variable assignment
# I'm making an assumption that the file will not contain any complicated code,
# or features that would be version-dependent. Since Horizon aims for
# compatibility with common systems, this should be a fair assumption.
@utils.idempotent
def _read_config(path):
    with open(path, 'r') as f:
        conf_content = f.read()
    return _parse_config(conf_content)


def _parse_config(conf_content):

    conf_ast = ast.parse(conf_content)
    config = {}

    for statement in conf_ast.body:
        if not isinstance(statement, ast.Assign):
            # ignore complicated statements
            continue

        target = statement.targets[0]
        if isinstance(target, ast.Name):
            name = target.id
        elif (isinstance(target, ast.Subscript) and
              isinstance(target.value, ast.Name) and
              isinstance(target.slice, ast.Index) and
              isinstance(target.slice.value, ast.Str)):
            # cheat a bit since this name is illegal for variable
            name = "%s[%s]" % (target.value.id, target.slice.value.s)
        else:
            logger.warning('cannot parse assignment at line %i',
                           statement.lineno)
            continue

        try:
            config[name] = _resolve_constant(statement.value)
        except NotConstant:
            logger.warning('value assigned to %s in horizon config could not '
                           'be parsed as a constant', name)
            continue

    return config


def _checks_config(f):
    @functools.wraps(f)
    def wrapper(config):
        try:
            path = os.path.join(config['dir'], 'local_settings.py')
            conf = _read_config(path)
        except EnvironmentError:
            return TestResult(Result.SKIP, 'cannot read horizon config file')
        return f(conf)
    return wrapper


def _conf_location():
    return {'dir': '/etc/openstack-dashboard'}


def _conf_details():
    config = _conf_location().copy()
    config['user'] = 'root'
    config['group'] = 'horizon'
    return config


@test_class.explanation("""
    Protection name: Config permissions

    Check: Are horizon config permissions ok

    Purpose: Horizon config files contain authentication
    details and need to be protected. Ensure that
    they're only available to the service.
    """)
@test_class.set_mapping("OpenStack:Check-Dashboard-01",
                        "OpenStack:Check-Dashboard-02")
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
    files = ['nova.conf',
             'api-paste.ini',
             'policy.json',
             'rootwrap.conf',
             ]
    for f in files:
        path = os.path.join(config['dir'], f)
        result.add_result(path,
                          utils.validate_permissions(path, 0o640, user.pw_uid,
                                                     group.gr_gid))
    return result


@test_class.explanation("""
    Protection name: Secure CSRF cookie

    Check: Verify that the CSRF cookies have the secure attribute

    Purpose: Prevent sending the CSRF cookie over unencrypted
    connections. This makes certain classes of attack harder.
    """)
@test_class.set_mapping("OpenStack:Check-Dashboard-04")
@test_class.takes_config(_conf_location)
@_checks_config
def csrf_cookie(conf):
    if conf.get('CSRF_COOKIE_SECURE', True):
        return TestResult(Result.PASS)
    else:
        return TestResult(Result.FAIL, 'CSRF_COOKIE_SECURE should be enabled')


@test_class.explanation("""
    Protection name: Secure the session cookie

    Check: Verify that the session cookies have the secure attribute

    Purpose: Prevent sending the session cookie over unencrypted
    connections. This makes session hijacking harder.
    """)
@test_class.set_mapping("OpenStack:Check-Dashboard-05")
@test_class.takes_config(_conf_location)
@_checks_config
def session_cookie(conf):
    if conf.get('SESSION_COOKIE_SECURE', True):
        return TestResult(Result.PASS)
    else:
        return TestResult(Result.FAIL,
                          'SESSION_COOKIE_SECURE should be enabled')


@test_class.explanation("""
    Protection name: Prevent session cookie access

    Check: Verify that the session cookies have the httponly attribute

    Purpose: Prevent the session cookie from being accessed by the
    scripts running on the website. This makes session hijacking
    harder.
    """)
@test_class.set_mapping("OpenStack:Check-Dashboard-06")
@test_class.takes_config(_conf_location)
@_checks_config
def session_cookie_http(conf):
    if conf.get('SESSION_COOKIE_HTTPONLY', True):
        return TestResult(Result.PASS)
    else:
        return TestResult(Result.FAIL,
                          'SESSION_COOKIE_HTTPONLY should be enabled')


@test_class.explanation("""
    Protection name: Prevent autocompletion on login forms

    Check: Verify that logins are not autocompleted

    Purpose: Disabling login data autocompletion makes it harder
    to find out any part of the credentials used by the previous user.
    """)
@test_class.set_mapping("OpenStack:Check-Dashboard-07")
@test_class.takes_config(_conf_location)
@_checks_config
def password_autocomplete(conf):
    setting = conf.get('HORIZON_CONFIG[password_autocomplete]', "off")
    if setting in (False, "off"):
        return TestResult(Result.PASS)
    else:
        return TestResult(Result.FAIL,
                          'password_autocomplete should be disabled')


@test_class.explanation("""
    Protection name: Disable password reveal

    Check: Verify that password fields are not revealed

    Purpose: Disabling login data autocompletion makes it harder
    to find out any part of the credentials used by the previous user.
    """)
@test_class.set_mapping("OpenStack:Check-Dashboard-08")
@test_class.takes_config(_conf_location)
@_checks_config
def password_reveal(conf):
    setting = conf.get('HORIZON_CONFIG[disable_password_reveal]', False)
    if setting:
        return TestResult(Result.PASS)
    else:
        return TestResult(Result.FAIL,
                          'password_autocomplete should be disabled')
