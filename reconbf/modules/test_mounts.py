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

import os
import re
import subprocess


MOUNT_RE_LINUX = re.compile(b"""
    (.+)  # source
    \s on \s
    (.+)  # destination
    \s type \s
    (.+)  # type
    \s
    \(([^)]*)\)  # options
    """, re.VERBOSE)
MOUNT_RE_BSD = re.compile(b"""
    (.+)  # source
    \s on \s
    (.+)  # destination
    \s \(
    (.+),  # type
    ([^)]*)\)  # options
    """, re.VERBOSE)


@utils.idempotent
def _get_mounts():
    try:
        mounts = subprocess.check_output(['mount'])
    except (subprocess.CalledProcessError, OSError):
        return None

    results = []

    for mount in mounts.splitlines():
        for RE in (MOUNT_RE_LINUX, MOUNT_RE_BSD):
            m = RE.match(mount.strip())
            if m:
                break
        if not m:
            logger.warning("could not parse mount line '%s'", mount)
            continue
        results.append((
            m.group(1),
            m.group(2),
            m.group(3),
            m.group(4).split(b','),
            ))

    return results


def _find_mount_point(mounts, path):
    candidate = None

    for mount in mounts:
        common_prefix = os.path.commonprefix([mount[1], path])
        if common_prefix == path:
            return mount

        if common_prefix == mount[1]:
            if not candidate:
                candidate = mount
            else:
                if len(candidate[1]) < len(mount[1]):
                    candidate = mount

    # None will never be returned in practice - at least / will match
    return candidate


def _conf_nosuid():
    return ['/dev', '/dev/pts', '/dev/shm', '/home', '/proc', '/run', '/sys',
            '/tmp']


@test_class.explanation("""
    Protection name: Directories mounted with nosuid

    Check: Verify whether configured directories are mounted
    with a nosuid option.

    Purpose: Most directories are not expected to hold
    setuid/setgid binaries. Turning on the nosuid option on their
    mount entries ensures the system is hardened against some
    exploits relying on local file manipulation.
    """)
@test_class.takes_config(_conf_nosuid)
def no_suid(nosuid_mounts):
    mounts = _get_mounts()

    results = GroupTestResult()
    for destination in nosuid_mounts:
        point = _find_mount_point(mounts, destination.encode('utf-8'))

        if b'nosuid' in point[3]:
            results.add_result(destination, TestResult(Result.PASS))
        else:
            dest = point[1].decode('utf-8', errors='replace')
            msg = "suid binaries allowed on %s" % (dest,)
            results.add_result(destination, TestResult(Result.FAIL, msg))
    return results


def _conf_noexec():
    return ['/proc', '/run', '/sys', '/tmp']


@test_class.explanation("""
    Protection name: Directories mounted with noexec

    Check: Verify whether configured directories are mounted
    with a noexec option.

    Purpose: Most directories are not expected to hold
    executable binaries. Turning on the noexec option on their
    mount entries ensures the system is hardened against some
    exploits relying on local file manipulation.
    """)
@test_class.takes_config(_conf_noexec)
def no_exec(noexec_mounts):
    mounts = _get_mounts()

    results = GroupTestResult()
    for destination in noexec_mounts:
        point = _find_mount_point(mounts, destination.encode('utf-8'))

        if b'noexec' in point[3]:
            results.add_result(destination, TestResult(Result.PASS))
        else:
            dest = point[1].decode('utf-8', errors='replace')
            msg = "executable files allowed on %s" % (dest,)
            results.add_result(destination, TestResult(Result.FAIL, msg))
    return results
