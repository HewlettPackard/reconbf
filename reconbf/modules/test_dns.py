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

import reconbf.lib.test_class as test_class
from reconbf.lib.result import TestResult
from reconbf.lib.result import Result
import socket


@test_class.explanation(
    """
    Protection name: Default DNS domain name check.

    Check: Ensures that a default domain name is set.

    Purpose: A default hostname should be set in the
    /etc/hostname file, so that traffic can be routed
    to the proper host. In the event that a hostname is
    not set a user set this information which allows for
    possibly intercept and manipulate traffic or other
    types of malicious behavior on the local network.
    """)
def test_dns_name():
    try:
        host = socket.gethostname()
    except Exception:
        return TestResult(Result.SKIP, notes='Unable to find hostname.')

    if host:
        result = Result.PASS
        notes = 'Default hostname is %s.' % host
    else:
        result = Result.FAIL
        notes = 'Hostname is empty!'
    return TestResult(result, notes)


@test_class.explanation(
    """
    Protection name: Default DNS search domain check.

    Check: Ensures that an entry exists in /etc/resolv.conf
    for default DNS search domain.

    Purpose: Domain Name System (DNS) search domains should be
    set in the /etc/resolv.conf file as missing information can
    lead to potential exploitation such as insertion of entries
    that would result in name resolution requests to be serviced
    by a rogue DNS.
    """)
def test_default_dns_search():
    text = 'search '
    try:
        fp = open('/etc/resolv.conf', 'r')
    except IOError:
        return TestResult(Result.SKIP, notes="File /etc/resolv.conf " +
                                             "can't be opened for reading!")

    f = fp.read()

    if f.find(text):
        result = Result.PASS
        notes = 'Default search domain exists.'
    else:
        result = Result.FAIL
        notes = 'Default search domain does not exist!'
    return TestResult(result, notes)

    fp.close()
