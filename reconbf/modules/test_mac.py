from reconbf.lib.logger import logger
import reconbf.lib.test_class as test_class
from reconbf.lib.test_result import Result
from reconbf.lib.test_result import TestResult

from subprocess import PIPE
from subprocess import Popen


@test_class.explanation(
    """
    Protection name: SELinux installed

    Check: Run sestatus command and check the output

    Purpose: Mandatory Access Controls such as AppArmor and SELinux should be
    installed in order to confine applications to the leas privilege required
    to run them.
    """)
def test_selinux():
    """Uses return from sestatus command to ensure SELinux is installed

    :returns: A TestResult object containing the result and, on failure,
    notes explaining why it did not pass.
    """

    # logger
    return_result = None
    logger.debug("[*] Attempting to validate SELinux is installed.")

    # check
    try:
        # if sestatus_return is stdout:
        cmd = 'sestatus'
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()

        if b'sestatus: not found' in stderr:
            reason = "SELinux is not installed."
            logger.info("[-] {}".format(reason))
            return_result = TestResult(Result.FAIL, notes=reason)

        elif b'disabled' in stdout:
            reason = "SELinux is disabled."
            logger.info("[-] {}".format(reason))
            return_result = TestResult(Result.FAIL, notes=reason)

        elif b'permissive' in stdout:
            reason = "SELinux is permissive (disabled but logging)."
            logger.info("[-] {}".format(reason))
            return_result = TestResult(Result.FAIL, notes=reason)

        elif b'enforcing' in stdout:
            reason = "SELinux is installed and enforcing."
            logger.info("[-] {}".format(reason))
            return_result = TestResult(Result.PASS)

        else:
            # wth?
            logger.debug("[*] Unexpected error while looking for SELinux: "
                         "    Standard Output from sestatus command: [{}]"
                         "    Standard Error from sestatus command: [{}]".
                         format(stdout, stderr))
            return_result = TestResult(Result.SKIP, notes="Unexpected error.")

    except EnvironmentError as e:
        # log no selinux
        logger.debug("[*] Unexpected error running sestatus: [{}]".format(e))
        return_result = TestResult(Result.SKIP, notes="Unexpected error.")

    return return_result


# AppArmor check - look for /etc/apparmor directory.
@test_class.explanation(
    """
    Protection name: AppArmor installed

    Check: Run apparmor_status command and check the output

    Purpose: Mandatory Access Controls such as AppArmor and SELinux should be
    installed in order to confine applications to the leas privilege required
    to run them.
    """)
def test_apparmor():
    """Uses return from apparmor_status to check installation and level
    at which AppArmor is monitoring.

    :returns: A TestResult object containing the result and notes
    explaining why it did not pass.
    """

    # initial configurations
    return_result = None
    logger.debug("[*] Attempting to validate AppArmor is installed.")

    # check
    try:
        cmd = 'apparmor_status'
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()

        if b'apparmor_status: command not found' in stderr:
            reason = "AppArmor is not installed."
            logger.debug("[-] {}".format(reason))
            return_result = TestResult(Result.FAIL, notes=reason)

        # enforcing check, no /'s = no directories
        elif b"//" not in stdout:
            reason = "AppArmor has no modules loaded."
            logger.info("[-] {}".format(reason))
            return_result = TestResult(Result.FAIL, notes=reason)

        elif b"//" in stdout:
            reason = "AppArmor is installed and policy is loaded."
            logger.info("[+] {}".format(reason))
            return_result = TestResult(Result.PASS)
        else:
            # wth?
            logger.debug("[*] Unexpected error while looking for AppArmor: "
                         "    Standard Output from sestatus command: [{}]"
                         "    Standard Error from sestatus command: [{}]".
                         format(stdout, stderr))
            return_result = TestResult(Result.SKIP, notes="Unexpected error.")

    except EnvironmentError as e:
        logger.debug("[*] Unexpected error running apparmor_status: [{}]".
                     format(e))
        return_result = TestResult(Result.SKIP, notes="Unexpected error.")

    return return_result
