from reconbf.lib.logger import logger
import reconbf.lib.test_class as test_class
import reconbf.lib.test_config as test_config
from reconbf.lib.test_result import GroupTestResult
from reconbf.lib.test_result import Result
from reconbf.lib.test_result import TestResult
import reconbf.lib.test_utils as test_utils
from reconbf.lib.test_utils import ValNotFound

from subprocess import PIPE
from subprocess import Popen


@test_class.takes_config
@test_class.explanation(
    """
    Protection name: Bash not vulnerable to shellshock

    Check: Runs shellshock test payload and validates output

    Purpose: A version of bash on the system which is vulnerable to shellshock
    can expose the system to many types of attacks.  There is no good way to
    take stock of how many processes running on they system use Bash in a
    potentially vulnerable way, so the only way to prevent exploitation is to
    use a version of bash which has been patched.
    """)
def test_shellshock(config):
    logger.debug("[*] Testing shell for 'shellshock/bashbug' vulnerability.")

    try:
        cmd = config['exploit_command']
    except KeyError:
        logger.error("[-] Can't find exploit command for shellshock test")
    else:

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()

        if 'vulnerable' in stdout:
            reason = "System is vulnerable to Shellshock/Bashbug."
            logger.info("[-] {}".format(reason))
            result = Result.FAIL
        else:
            reason = "System is not vulnerable to Shellshock/Bashbug."
            logger.info("[+] {}".format(reason))
            result = Result.PASS
        return TestResult(result, reason)


@test_class.takes_config
@test_class.explanation(
    """
    Protection name: Sysctl settings set securely

    Check: Validates that sysctl values are set as specified in the
    configuration file.

    Purpose: Sysctl is used to configure kernel parameters. Many of these
    parameters can be used to tune and harden the security of a system. This
    check verifies that secure values have been used where applicable.
    """)
def test_sysctl_values(config):
    results = GroupTestResult()

    try:
        config_file = config['config_file']
    except KeyError:
        logger.error("[-] Can't find definition for 'config_file' in module's "
                     "settings, skipping test")
        return TestResult(Result.SKIP, "No proper config file defined")

    sysctl_reqs = test_config.get_reqs_from_file(config_file)
    if not sysctl_reqs:
        return TestResult(Result.SKIP, "Unable to load module config file")

    else:
        for requirement in sysctl_reqs:
            cur_result = None
            notes = ""
            # valid tests must have a key and allowed values
            if 'key' in requirement and 'allowed_values' in requirement:

                # name a test with specified name if it exists, otherwise just
                # use the key
                if 'name' in requirement:
                    test_name = "Sysctl check for " + requirement['name']
                else:
                    test_name = "Sysctl check for " + requirement['key']

                val_str = requirement['allowed_values'].replace(' ', '')
                allowed_values = val_str.split(',')

                try:
                    value = test_utils.get_sysctl_value(requirement['key'])
                except ValNotFound:
                    cur_result = Result.SKIP
                    notes = "Could not find a value for sysctl key { "
                    notes += requirement['key'] + " }"
                else:
                    if value in allowed_values:
                        cur_result = Result.PASS
                    else:
                        cur_result = Result.FAIL
                        notes = "Key { " + requirement['key']
                        notes += " } expected one of { " + val_str
                        notes += " } but got " + value
                results.add_result(test_name,
                                   TestResult(cur_result, notes=notes))

            else:
                logger.info("[-] Got malformed requirement {}".
                            format(requirement))
    return results


@test_class.explanation("""
    Protection name: Certificate expiration check.

    Check: Run the command "openssl verify cer.pem" and ensure the
    stdout returns "OK" in the message.

    Purpose: Certificates create a level of trust between the system
    and the packages and pages that are signed with the certificates
    private key. Ensuring that these certificates are both not expired
    and are properly created certificiates will help confirm that
    whatever communication or package that is received is valid.
    """)
def test_certs():
    logger.debug("[*] Testing bundled certificate validity & expiration.")

    certList = []
    certStore = '/etc/ssl/certs'
    result = None
    notes = ""

    # use test_utils to get list of certificates
    certList = test_utils.get_files_list_from_dir(certStore)

    if certList is None:
        notes = "/etc/ssl/certs is empty, please check on-system certificates."
        logger.debug("[*] {}".format(notes))
        result = Result.SKIP
        return TestResult(result, notes)

    for cert in certList:
        try:
            p = Popen(['openssl', 'verify', cert], stdout=PIPE, shell=False)
            stdout = p.communicate()
            if "OK" in stdout[0]:
                logger.debug("[+] Certificate verification success for: {}".
                             format(cert))
                if result is None:
                    result = Result.PASS
            else:
                result = Result.FAIL
                if notes is "":
                    notes += "Error validating certificate: " + cert
                else:
                    notes += ", " + cert
                logger.debug("[-] Certificate verification failure for: {}".
                             format(cert))

        except ValueError as e:
            notes = "Error running 'openssl verify " + cert + "'"
            logger.debug("[*] {}. \n   Error: {}".format(notes, e))
            result = Result.SKIP

    logger.debug("[*] Completed on-system certificate validation tests.")
    return TestResult(result, notes)
