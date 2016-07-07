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
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult
from reconbf.lib import utils

from subprocess import check_output


@test_class.explanation(
    """
    Protection name: NX (No-eXecute) protection is enabled

    Check: First line in the system dmesg indicates if it is enabled

    Purpose: The NX bit indicates if the architecture has marked
    specific areas of memory as non-executable (known as executable
    space protection) and helps preventing certain types of buffer
    overflow attacks.
    """)
def test_NX():
    logger.debug("Checking if NX (or NX emulation) is present.")

    output = check_output(["dmesg"])
    if b'NX (Execute Disable) protection: active' in output:
        reason = "NX protection active in BIOS."
        logger.debug(reason)
        result = Result.PASS

    else:
        # not active
        reason = "NX protection disabled in BIOS."
        logger.debug(reason)
        result = Result.FAIL

    return TestResult(result, reason)


@test_class.explanation(
    """
    Protection name: /dev/mem device blocks non-device access

    Check: in /proc/config.gz the CONFIG_STRICT_DEVMEM line is
    uncommented and set to equal 'y'

    Purpose: Some applications are built to require access to physical
    memory in the user-space (such as X windows), which was provided
    by the /dev/mem device. This check ensures that only other devices
    have access to the kernel memory, and thus does not allow a
    malicious user or program the ability to view or change data.
    """)
def test_devmem():
    # initial configurations
    reason = " "
    logger.debug("Attempting to validate /dev/mem protection.")
    result = Result.FAIL  # set fail by default?

    # check kernel config - CONFIG_STRICT_DEVMEM=y
    try:
        devmem_val = utils.kconfig_option('CONFIG_STRICT_DEVMEM')

        if devmem_val == 'y':
            reason = "/dev/mem protection is enabled."
            logger.debug(reason)
            result = Result.PASS
        elif devmem_val == 'n':
            reason = "/dev/mem protection is not enabled."
            logger.debug(reason)
            result = Result.FAIL
        else:
            result = Result.SKIP
            reason = "Cannot find the kernel config or option"

    except IOError as e:
        reason = "Error opening /proc/config.gz."
        logger.debug("Unable to open /proc/config.gz.\n"
                     "    Exception information: [ {} ]".format(e))
        result = Result.SKIP

    return TestResult(result, reason)
