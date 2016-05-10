import reconbf.lib.test_class as test_class
from reconbf.lib.result import TestResult
from reconbf.lib.result import Result
import platform
import subprocess


def _check_packages_ubuntu():
    res = subprocess.check_output(['ubuntu-support-status',
                                   '--show-unsupported'])
    lines = res.splitlines()

    for line in lines:
        if not line.startswith(b'You have '):
            continue
        if b'that are unsupported' not in line:
            continue

        if line.startswith(b"You have 0 packages"):
            return TestResult(Result.PASS, "Only supported packages installed")
        else:
            if bytes is not str:
                line = line.decode('utf-8', errors='replace')
            return TestResult(Result.FAIL, line.strip())

    return TestResult(Result.FAIL, "Unexpected ubuntu-support-status response")


@test_class.explanation(
    """
    Protection name: Supported packages

    Check: Ensures that all installed packages are still
    marked as supported.

    Purpose: Some distributions will mark the packages as supported
    either in specific versions, or for a specific period of time.
    Unsupported packages will not receive security updates, therefore
    they should be validated / replaced if possible.
    """)
def test_supported_packages():
    try:
        distro, _version, _name = platform.linux_distribution()
    except Exception:
        return TestResult(Result.SKIP, "Could not detect distribution")

    if distro == 'Ubuntu':
        return _check_packages_ubuntu()
    else:
        return TestResult(Result.SKIP, "Unknown distribution")
