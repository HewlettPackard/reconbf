from reconbf.lib.logger import logger
import reconbf.lib.test_class as test_class
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult
from reconbf.lib.result import GroupTestResult
from reconbf.lib import utils


@utils.idempotent
def _get_login_defs_config():
    config = {}

    try:
        with open('/etc/login.defs', 'r') as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue
                if line.startswith('#'):
                    continue

                try:
                    key, val = line.split()
                    config[key] = val
                except ValueError:
                    logger.debug("could not parse '%s'", line)
                    continue
    except EnvironmentError:
        logger.warning("cannot read the login.defs config")
        return None

    return config


@test_class.explanation(
    """
    Protection name: Logging of failed logins

    Check: Make sure that login failures are logged

    Purpose: Failed logins provide evidence of attempted access,
    as well as other information which may be helpful in
    stopping brute force attacks on accounts.
    """)
def failed_logins_logged():
    config = _get_login_defs_config()
    if config is None:
        return TestResult(Result.SKIP, "Failed to process the config")

    if config['FAILLOG_ENAB'] != 'yes':
        return TestResult(Result.FAIL, "Failing logins are not logged")
    else:
        return TestResult(Result.PASS, "Failed logins are logged")


@test_class.explanation(
    """
    Protection name: Logging of SU/SG access

    Check: Make sure that super user actions are logged

    Purpose: Explicit calls to super user actions should be
    logged. While this doesn't provide a full accounting of
    the super user actions, it provides useful information in
    most situations.
    """)
def su_logging():
    results = GroupTestResult()

    config = _get_login_defs_config()
    if config is None:
        return TestResult(Result.SKIP, "Failed to process the config")

    if config['SYSLOG_SU_ENAB'] != 'yes':
        result = TestResult(Result.FAIL, "actions not logged")
    else:
        result = TestResult(Result.PASS)
    results.add_result("su", result)

    if config['SYSLOG_SG_ENAB'] != 'yes':
        result = TestResult(Result.FAIL, "actions not logged")
    else:
        result = TestResult(Result.PASS)
    results.add_result("sg", result)

    return results
