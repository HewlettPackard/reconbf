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
from reconbf.lib.result import Result, TestResult


@test_class.explanation("""
    Protection name: SecureBoot

    Check: Ensures that the current system has been booted with the SecureBoot
    option active and it's been processed correctly.

    Purpose: Secure Boot works by placing the root of trust in firmware. It
    allows booting kernel/system verified by the EFI and hardware itself.
    """)
def test_secureboot():
    EFI_DIR = '/sys/firmware/efi/efivars/'
    # SecureBoot from Global Efi Variables
    EFI_BOOT = EFI_DIR + 'SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
    try:
        with open(EFI_BOOT, 'rb') as f:
            data = f.read(5)
    except IOError:
        return TestResult(Result.SKIP,
                          "EFI variables not available on the system")

    if len(data) != 5:
        # efivars contain 4 bytes of attributes + data
        return TestResult(Result.SKIP,
                          "EFI variable does not contain data")

    if data[4:5] == b"\x01":
        return TestResult(Result.PASS,
                          "SecureBoot is active")
    else:
        return TestResult(Result.FAIL,
                          "SecureBoot is diabled")
