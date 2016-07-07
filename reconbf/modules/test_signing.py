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
from reconbf.lib.result import GroupTestResult, Result, TestResult


@test_class.explanation("""
    Protection name: Kernel module signing

    Check: Kernel will check module signatures before loading.

    Check: Kernel will prevent unsigned modules from loading.

    Check: Kernel has not loaded any unsigned modules.

    Purpose: Preventing unsigned modules from loading can make sure that bad
    object is not loaded accidentally, or maliciously.
    """)
def test_module_signing():
    results = GroupTestResult()

    enabled_check = "Module signature checking enabled"
    forced_check = "Module signature checking forced"
    tainted_check = "Present modules"

    if utils.kconfig_option("CONFIG_MODULE_SIG") == "y":
        result = TestResult(Result.PASS, notes="Enabled")
        available = True
    else:
        result = TestResult(Result.FAIL, notes="Disabled")
        available = False

    results.add_result(enabled_check, result)
    if not available:
        result = TestResult(Result.SKIP, notes="Not available")
        results.add_result(forced_check, result)
        results.add_result(tainted_check, result)
        return results

    if utils.kconfig_option("CONFIG_MODULE_SIG_FORCE") == "y":
        result = TestResult(Result.PASS, notes="Enabled")
    else:
        result = TestResult(Result.FAIL, notes="Disabled")
    results.add_result(forced_check, result)

    try:
        with open('/proc/sys/kernel/tainted', 'r') as f:
            contents = f.read()
        level = int(contents)
        if level & 8192:
            result = TestResult(Result.FAIL, notes="Unsigned module detected")
        else:
            result = TestResult(Result.PASS,
                                notes="All loaded modules are signed")
    except (IOError, ValueError):
        result = TestResult(Result.FAIL, notes="Taint level cannot be read")

    results.add_result(tainted_check, result)
    return results
