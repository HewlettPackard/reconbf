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
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult

import os
import platform


@test_class.explanation(
    """
    Protection name: USB authorization

    Check: Check if USB hosts accept all connected devices

    Purpose: Linux can ensure that USB devices are not active
    until they're explicitly authorized. Setting flag
    /sys/bus/usb/devices/usbX/authorized_default to 0 makes
    new devices disabled by default.
    This can protect against physical attacks via connected
    HID, storage, or exploitation device.
    """)
def usb_authorization():
    if platform.system() != 'Linux':
        return TestResult(Result.SKIP, "available only on Linux")

    open_hosts = []
    hosts = [dev for dev in os.listdir('/sys/bus/usb/devices') if
             dev.startswith('usb')]

    for host in hosts:
        auth_file = os.path.join('/sys/bus/usb/devices', host,
                                 'authorized_default')
        if not os.path.isfile(auth_file):
            continue

        with open(auth_file, 'r') as f:
            contents = f.read().strip()

        if contents != '0':
            open_hosts.append(host)

    if not hosts:
        return TestResult(Result.SKIP, "no USB hosts found")

    if not open_hosts:
        return TestResult(Result.PASS, "no open USB hosts")

    results = GroupTestResult()
    for host in open_hosts:
        results.add_result(host, TestResult(
            Result.FAIL, "USB host accepts all devices by default"))
    return results
