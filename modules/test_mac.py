import lib.test_utils as test_utils
import lib.test_class as test_class
from lib.test_result import TestResult
from lib.test_result import Result
from subprocess import Popen, PIPE

@test_class.tag("software", "system")
@test_class.explanation(
    """
    Mandatory Access Controls such as AppArmor and SELinux should be
    installed in order to confine applications to the leas privilege
    required to run them.
    """)
def test_selinux():
    '''
    Uses return from sestatus command to ensure SELinux is installed

    :return: A TestResult object containint the result and, on failure,
    notes explaining why it did not pass.
    '''

    #logger
    logger = test_utils.get_logger()
    return_result = None
    logger.debug("[*] Attempting to validate SELinux is installed.")

    # check
    try:
        #if sestatus_return is stdout:
        cmd = 'sestatus'
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()

        if 'sestatus: not found' in stderr:
            reason = "SELinux is not installed."
            logger.info("[-] " + reason)
            return_result = TestResult(Result.FAIL, notes=reason)

        elif 'disabled' in stdout:
            reason = "SELinux is disabled."
            logger.info("[-]" + reason)
            return_result = TestResult(Result.FAIL, notes=reason)

        elif 'permissive' in stdout:
            reason = "SELinux is permissive (disabled but logging)."
            logger.info("[-] " + reason)
            return_result = TestResult(Result.FAIL, notes=reason)

        elif 'enforcing' in stdout:
            reason = "SELinux is installed and enforcing."
            logger.info("[-] " + reason)
            return_result = TestResult(Result.PASS)

        else:
            #wth?
            logger.debug("[*] Unexpected error while looking for SELinux: {")
            logger.debug("    Standard Output from sestatus command: {")
            logger.debug(stdout)
            logger.debug("    }")
            logger.debug("    Standard Error from sestatus command: {")
            logger.debug(stderr)
            logger.debug("    }  }")
            return_result = TestResult(Result.SKIP, notes="Unexpected error.")

    except EnvironmentError as e:
        #log no selinux
        logger.debug("[*] Unexpected error running sestatus: {")
        logger.debug(e)
        logger.debug("}")
        return_result = TestResult(Result.SKIP, notes="Unexpected error.")

    return return_result


# AppArmor check - look for /etc/apparmor directory.
def test_apparmor():
    '''
    Uses return from apparmor_status to check installation and level
    at which AppArmor is monitoring.

    :return: A TestResult object containing the result and notes
    explaining why it did not pass.
    '''

    #initial configurations
    logger = test_utils.get_logger()
    return_result = None
    logger.debug("[*] Attempting to validate AppArmor is installed.")

    # check
    try:
        cmd = 'apparmor_status'
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()

        if 'apparmor_status: command not found' in stderr:
            reason = "AppArmor is not installed."
            logger.debug("[-] " + reason)
            return_result = TestResult(Result.FAIL, notes=reason)

        #enforcing check, no /'s = no directories
        elif "//" not in stdout:
            reason = "AppArmor has no modules loaded."
            logger.info("[-] " + reason)
            return_result = TestResult(Result.FAIL, notes=reason)

        elif "//" in stdout:
            reason = "AppArmor is installed and policy is loaded."
            logger.info("[+] " + reason)
            return_result = TestResult(Result.PASS)
        else:
            #wth?
            logger.debug("[*] Unexpected error while looking for AppArmor: {")
            logger.debug("    Standard Output from sestatus command: {")
            logger.debug(stdout)
            logger.debug("    }")
            logger.debug("    Standard Error from sestatus command: {")
            logger.debug(stderr)
            logger.debug("    }  }")
            return_result = TestResult(Result.SKIP, notes="Unexpected error.")

    except EnvironmentError as e:
        logger.debug("[*] Unexpected error running apparmor_status: {")
        logger.debug(e)
        logger.debug("}")
        return_result = TestResult(Result.SKIP, notes="Unexpected error.")

    return return_result