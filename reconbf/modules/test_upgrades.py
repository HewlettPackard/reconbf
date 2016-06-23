import reconbf.lib.test_class as test_class
from reconbf.lib.result import TestResult
from reconbf.lib.result import Result

import os
import platform


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

    if distro in ('Ubuntu', 'debian'):
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
