from reconbf.lib import test_class
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
