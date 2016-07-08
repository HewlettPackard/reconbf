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
import reconbf.lib.test_class as test_class
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import TestResult
from reconbf.lib.result import Result

import os
import platform
import string


@test_class.explanation(
    """
    Protection name: Reboot required

    Check: Verify if the system thinks a reboot is required

    Purpose: Some distributions will report whether a reboot is
    required due to recently installed packages. This usually
    means a new binary cannot be easily restarted: like the
    kernel or the init system.
    """)
def reboot_required():
    try:
        distro, _version, _name = platform.linux_distribution()
    except Exception:
        return TestResult(Result.SKIP, "Could not detect distribution")

    if distro in ('Ubuntu', 'Debian'):
        if os.path.isfile('/var/run/reboot-required'):
            try:
                with open('/var/run/reboot-required.pkgs', 'r') as f:
                    packages = set(line.strip() for line in f.readlines())
            except Exception:
                packages = None

            if packages:
                packages = ', '.join(sorted(packages))
                msg = "Reboot is required to update: %s" % packages
            else:
                msg = "Reboot is required"
            return TestResult(Result.FAIL, msg)

        else:
            return TestResult(Result.PASS)

    else:
        return TestResult(Result.SKIP, "Unknown distribution")


@test_class.explanation(
    """
    Protection name: Running processes have all corresponding files

    Check: Checks that each process running on the system uses
    files which are present on the disk.

    Purpose: Usually every running process will have the corresponding
    executable file and library available all the time. Anything
    different is an uncommon situation. It can happen for example
    because: file was deleted on purpose to avoid detection, package
    has been upgraded but the process was not restarted (potentially
    still vulnerable), etc.
    """)
def missing_process_binaries():
    results = GroupTestResult()

    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue

        try:
            main_binary = os.readlink(os.path.join('/proc', pid, 'exe'))

            missing_main = False
            missing = set()

            links = os.listdir(os.path.join('/proc', pid, 'map_files'))
            for link in links:
                link_path = os.readlink(os.path.join('/proc', pid, 'map_files',
                                                     link))
                if link_path.endswith(' (deleted)'):
                    if link_path == main_binary:
                        missing_main = True
                    else:
                        link_path = link_path[:-10]
                        # only check libraries, data files can go missing
                        # without issues
                        file_name = os.path.basename(link_path)
                        if file_name.endswith('.so') or '.so.' in file_name:
                            missing.add(link_path)

            if main_binary.endswith(' (deleted)'):
                main_binary = main_binary[:-10]

            process = "pid %s, %s" % (pid, main_binary)
            missing_list = []
            if missing_main:
                missing_list.append('main binary')
            missing_list.extend(sorted(missing))

            if missing_list:
                msg = "Missing: %s" % ', '.join(missing_list)
                results.add_result(process, TestResult(Result.FAIL, msg))
            else:
                results.add_result(process, TestResult(Result.PASS))

        except EnvironmentError:
            # this pid can disappear at any point, so on any read failure,
            # just continue with the next process
            continue

    return results


def _parse_deb_repo_line(line):
    # this parses only the one-line format, because honestly, who uses deb822
    # in their sources file...
    line = line.strip()

    # cut off the comments
    comment_pos = line.find('#')
    if comment_pos != -1:
        line = line[:comment_pos]

    # ignore empty lines
    if not line:
        return

    # everything's split by whitespace
    parts = line.split()
    pkg_type = parts.pop(0)
    while parts:
        if '=' in parts[0]:
            # just ignore the options...
            parts.pop(0)
        else:
            break

    if not parts:
        logger.warning('deb entry "%s" missing uri, ignoring', line)
        return
    uri = parts.pop(0)

    if not parts:
        logger.warning('deb entry "%s" missing suite, ignoring', line)
        return
    suite = parts.pop(0)
    components = parts
    return {
        'type': pkg_type,
        'uri': uri,
        'suite': suite,
        'components': components,
        }


SOURCES_LIST_CHARS = set(string.ascii_letters + string.digits + '_-.')


def _get_deb_repos():
    repos = []
    files = ['/etc/apt/sources.list']

    try:
        for name in os.listdir('/etc/apt/sources.list.d'):
            if not name.endswith('.list'):
                continue
            if set(name).difference(SOURCES_LIST_CHARS):
                # unexpected characters in the name, ignored by apt by default
                continue

            files.append('/etc/apt/sources.list.d/' + name)
    except OSError:
        # if the directory cannot be read, it's ok to ignore it
        pass

    for name in files:
        try:
            with open(name, 'r') as f:
                for line in f:
                    repo = _parse_deb_repo_line(line)
                    if repo:
                        repos.append(repo)
        except EnvironmentError:
            logger.warning('cannot read repo list "%s"', name)
            continue

    return repos


@test_class.explanation(
    """
    Protection name: Security updates in repo lists

    Check: Will the package manager look at security
    updates when a standard system update is triggered.

    Purpose: Many systems use a different repository
    for standard releases and for security updates. This
    is due to multiple reasons (security-only update
    streams, mirror delays, etc.), but means a system
    may seem to be updating ok even if no security
    fixes are pulled.
    Currently, this test supports Debian and Ubuntu
    systems only.
    """)
def security_updates():
    try:
        distro, _version, version_name = platform.linux_distribution()
    except Exception:
        return TestResult(Result.SKIP, "Could not detect distribution")

    if distro in ('Ubuntu', 'Debian'):
        repos = _get_deb_repos()

        security_suite = version_name + '-security'
        found_security = False

        for repo in repos:
            if repo['type'] != 'deb':
                continue

            if distro == 'Ubuntu' and repo['suite'] == security_suite:
                found_security = True
                break
            if (distro == 'Debian' and 'http://security.debian.org' in
                    repo['uri']):
                found_security = True
                break

        if found_security:
            return TestResult(Result.PASS, "Security repo present")
        else:
            return TestResult(Result.FAIL,
                              "Upstream security repo not configured")

    else:
        return TestResult(Result.SKIP, "Unknown distribution")
