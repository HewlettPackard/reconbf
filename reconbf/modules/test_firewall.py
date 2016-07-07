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
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult

import collections
import subprocess


def _list_rules():
    try:
        output = subprocess.check_output(['iptables-save'])
    except (IOError, subprocess.CalledProcessError):
        # cannot get the list of rules for some reason
        return None

    lines = [line.strip() for line in output.splitlines()
             if not line.startswith(b'#')]
    return lines


def _get_default_policy(rules):
    """Get the default policy for each table/chain."""
    tables = collections.defaultdict(dict)
    current_table = None

    for rule in rules:
        if rule.startswith(b'*'):
            current_table = rule[1:]

        if rule.startswith(b':'):
            parts = rule[1:].split()
            tables[current_table][parts[0]] = parts[1]

    return tables


@test_class.explanation("""
    Protection name: Firewall whitelisting

    Check: Make sure that the firewall is configured to reject
    packets by default.

    Purpose: Creating whitelists is usually more secure than
    blacklists. Defaulting to dropping unknown traffic is a safer
    option in case of missed rules.
    """)
def firewall_whitelisting():
    rules = _list_rules()
    if rules is None:
        return TestResult(Result.SKIP, "Cannot retrieve iptables rules")

    targets = _get_default_policy(rules)
    if b'filter' not in targets:
        return TestResult(Result.SKIP, "Cannot find the filter table")

    failures = []

    filter_table = targets[b'filter']
    if b'INPUT' not in filter_table:
        return TestResult(Result.SKIP, "Filter table doesn't include INPUT")
    if b'FORWARD' not in filter_table:
        return TestResult(Result.SKIP, "Filter table doesn't include FORWARD")

    if filter_table[b'INPUT'] == b'ACCEPT':
        failures.append('INPUT')
    if filter_table[b'FORWARD'] == b'ACCEPT':
        failures.append('FORWARD')

    if failures:
        return TestResult(Result.FAIL,
                          "The following chains accept packets by "
                          "default: %s" % ', '.join(failures))
    else:
        return TestResult(Result.PASS, "Filter chains whitelist by default")
