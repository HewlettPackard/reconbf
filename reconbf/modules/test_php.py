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
from reconbf.lib import utils
from reconbf.lib.logger import logger
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult

import json
import os
import subprocess


def _find_checker(path):
    # check for project-specific checker
    command = os.path.join(
        path, 'vendor/sensiolabs/security-checker/security-checker')
    if os.path.isfile(command):
        return command

    # check for systemwide checker installation
    for path in os.environ.get('PATH', "").split(":"):
        command = os.path.join(path, 'security-checker')
        if os.path.isfile(command):
            return command

    return None


def _conf_app_paths():
    return []


@test_class.explanation("""
    Protection name: Composer modules security

    Check: Validate the list of installed php/composer modules
    against the sensio database of known vulnerabilities.
    The check requires open internet connection and the
    sensiolabs/security-checker module installed in the app.

    Purpose: Web applications may be vulnerable because of issues
    not solved by the systemwide upgrade systems. Sensiolabs
    maintains a database of issues in php/composer modules.
    More details about the issues can be found by either running
    the checker independently or checking:
    https://security.sensiolabs.org/check
    """)
@test_class.takes_config(_conf_app_paths)
def composer_security(app_paths):
    if not app_paths:
        return TestResult(Result.SKIP, "no web applications configured")

    results = GroupTestResult()

    for path in app_paths:
        try:
            with open(os.path.join(path, 'composer.lock'), 'r') as f:
                lock_contents = f.read()
        except EnvironmentError:
            results.add_result(path, TestResult(Result.SKIP,
                                                "composer.lock missing"))
            continue

        try:
            lock = json.loads(lock_contents)
        except ValueError:
            results.add_result(path, TestResult(
                Result.SKIP, "composer.lock cannot be parsed"))
            continue

        checker_found = False
        for package in lock.get('packages', []):
            if not isinstance(package, dict):
                continue
            if package.get('name') == 'sensiolabs/security-checker':
                checker_found = True
                break

        if not checker_found:
            results.add_result(path, TestResult(
                Result.SKIP,
                "sensiolabs/security-checker is not installed, cannot proceed"
                ))
            continue

        security_checker = _find_checker(path)
        if not security_checker:
            results.add_result(path, TestResult(
                Result.SKIP, "cannot find security-checker to execute"))
            continue

        try:
            proc = subprocess.Popen([
                security_checker, 'security:check', '--no-ansi', '--format',
                'json', '-n', path],
                stdout=subprocess.PIPE)
            (output, _) = proc.communicate()
        except (subprocess.CalledProcessError, OSError):
            results.add_result(path, TestResult(Result.FAIL,
                                                "checker failed to run"))
            continue

        try:
            issues = json.loads(output.decode('utf-8', errors='replace'))
        except ValueError:
            results.add_result(path, TestResult(
                Result.FAIL, "cannot parse checker's response"))
            continue

        if issues:
            results.add_result(path, TestResult(
                Result.FAIL,
                "%s: module has known vulnerabilities" % ', '.join(issues)))
        else:
            results.add_result(path, TestResult(Result.PASS))

    return results


def _find_all_inis(config_set):
    if not config_set:
        return []

    found = []

    # the first item should be just the main ini
    if os.path.isfile(config_set['ini_file']):
        found.append(config_set['ini_file'])
    else:
        logger.warning('expected "%s" to be a file, ignoring',
                       config_set['ini_file'])

    scan_dirs = config_set['ini_dirs'].split(':')
    for scan_dir in scan_dirs:
        if not os.path.isdir(scan_dir):
            continue

        for entry in sorted(os.listdir(scan_dir)):
            if not entry.endswith('.ini'):
                continue

            full_path = os.path.join(scan_dir, entry)
            if not os.path.isfile(full_path):
                continue

            found.append(full_path)

    return found


def _parse_php_config(path, config):
    # php ini files are nothing like ini files, they need special treatment
    # like skipping sections and converting values to booleans
    with open(path, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith(';'):  # skip comment
            continue
        if line.startswith('['):  # skip sections... because php
            continue

        key, _, val = line.partition('=')
        key = key.strip()
        val = val.strip()
        if not key:
            logger.warning('line "%s" is invalid php config, skipped', line)
            continue

        if not val:
            config[key] = None

        elif val == 'None':
            config[key] = None

        elif val in ('1', 'On', 'True', 'Yes'):
            config[key] = True

        elif val in ('0', 'Off', 'False', 'No'):
            config[key] = False

        elif val[0] == '"' and val[-1] == '"':
            config[key] = val[1:-1]

        else:
            config[key] = val

    return config


def _conf_ini_paths():
    options = {
        'allow_url_fopen': {'allowed': [False]},
        'allow_url_include': {'disallowed': [True]},
        'display_errors': {'allowed': [False, 'stderr']},
        'expose_php': {'disallowed': [True]},
        'open_basedir': {'allowed': "*"},
        }
    return {
        'cli': {
            'ini_file': '/etc/php/7.0/cli/php.ini',
            'ini_dirs': '/etc/php/7.0/cli/conf.d',
            'options': options,
            },
        'cgi': {
            'ini_file': '/etc/php/7.0/cgi/php.ini',
            'ini_dirs': '/etc/php/7.0/cgi/conf.d',
            'options': options,
            },
        'fpm': {
            'ini_file': '/etc/php/7.0/fpm/php.ini',
            'ini_dirs': '/etc/php/7.0/fpm/conf.d',
            'options': options,
            },
    }


@test_class.explanation("""
    Protection name: Protections in the php configuration

    Check: Validates known security-related options in PHP
    configuration.

    Purpose: Some options in the php.ini configs apply to
    most applications. This check verifies both that some
    options are turned off and that others are left as
    defaults. With the default config, the following options
    are checked:
    - allow_url_fopen: make sure fopen is only allowed to
                       local files
    - allow_url_include: make sure remote code files cannot
                         be included
    - display_errors: don't show php errors to page users
    - expose_php: don't expose php version - while it doesn't
                  improve security it prevents the site from
                  being indexed for future exploitation
    - open_basedir: only files within specified directories
                    should be possible to open by the php
                    application
    """)
@test_class.takes_config(_conf_ini_paths)
def php_ini(ini_paths):
    results = GroupTestResult()

    for set_name, config_set in ini_paths.items():
        inis = _find_all_inis(config_set)
        if not inis:
            logger.warning('no php config paths found for %s', set_name)
            results.add_result(set_name, TestResult(Result.SKIP,
                                                    'config not found'))
            continue

        config = {}
        for ini in inis:
            config = _parse_php_config(ini, config)

        for test, res in utils.verify_config(
                set_name, config, config_set['options'], needs_parsing=False):
            results.add_result(test, res)

    return results
