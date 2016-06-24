import reconbf.lib.test_class as test_class
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult

import os


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
