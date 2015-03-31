from subprocess import Popen
from subprocess import PIPE
import lib.test_class as test_class
import lib.test_utils as test_utils
from lib.test_result import GroupTestResult
from lib.test_result import TestResult
from lib.test_result import Result
from lib.test_utils import ValNotFound

@test_class.tag("software", "system")
@test_class.explanation(
    """
    AppArmor should be installed in order to confine applications to the
    least required privileges required to run them.
    """)
def test_app_armor_installed():
    expected = True
    actual = test_utils.check_path_exists('/sys/kernel/security/apparmor')

    if expected == actual:
        result = Result.PASS
    else:
        result = Result.FAIL

    return TestResult(result)


@test_class.tag("vulnerability", "system")
@test_class.takes_config
def test_shellshock(config):
    logger = test_utils.get_logger()
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
            logger.info("[-] " + reason)
            result = Result.FAIL
        else:
            reason = "System is not vulnerable to Shellshock/Bashbug."
            logger.info("[+] " + reason)
            result = Result.PASS
        return TestResult(result, reason)

@test_class.group_test
@test_class.takes_config
@test_class.explanation(
    """
    Sysctl is used to configure kernel parameters. Many of these parameters
    can be used to tune and harden the security of a system. This check
    verifies that secure values have been used where applicable.
    """)
@test_class.tag("system", "kernel")
def test_sysctl_values(config):
    logger = test_utils.get_logger()
    results = GroupTestResult()

    try:
        config_file = config['config_file']
        sysctl_reqs = test_utils.get_reqs_from_file(config_file)

    # things that are going to make us skip the test:
    #  1) Can't find entry for 'config_file' which points to the json file
    #     that actually lists the files and permissions to check
    #  2) Can't find/open that json file
    #  3) File isn't valid json
    except KeyError:
        logger = test_utils.get_logger()
        logger.error("[-] Can't find definition for 'config_file' in module's "
                     "settings, skipping test")

    # if we got exceptions when trying to read the config, skip the test
    except EnvironmentError:
        pass
    except ValueError:
        pass

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

                allowed_value_string = requirement['allowed_values'].replace(' ','')
                allowed_values = allowed_value_string.split(',')

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
                        notes += " } expected one of { " + allowed_value_string
                        notes += " } but got " + value
                results.add_result(test_name,
                                   TestResult(cur_result, notes=notes))

            else:
                logger.info("[-] Got malformed requirement " +
                            str(requirement))
    return results
