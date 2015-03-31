import lib.test_class as test_class
import lib.test_utils as test_utils
from lib.test_result import TestResult
from lib.test_result import Result

@test_class.tag("system", "config", "users")
@test_class.explanation(
    """
    Every user account should either have a password set or be disabled.  One
    common way for attackers to gain access to a system is to enumerate typical
    user accounts and try to log in with usual credentials, or even without
    credentials.  By ensuring all accounts have passwords or are disabled, it
    makes it harder for an attacker to gain a foothold in the system.
    """)
def test_accounts_nopassword():
    shadow_path = "/etc/shadow"
    shadow_lines = []
    logger = test_utils.get_logger()

    try:
        shadow_file = open(shadow_path, 'r')
    except IOError:
        logger.error("[-] Unable to read shadow file, skipping test")
        return TestResult(Result.SKIP, "Unable to read shadow file")
    else:
        shadow_lines = shadow_file.readlines()
        shadow_file.close()

    disabled = []
    locked = []
    passworded = []
    no_password = []

    for line in shadow_lines:
        try:
            account = line.split(':')[0]
            password = line.split(':')[1]
        except IndexError:
            logger.error("[-] Got malformed line in shadow file")
        else:
            # passwords which start with ! have been locked
            if password.startswith('!'):
                locked.append(account)
            # passwords which start with * have been disabled
            elif password.startswith('*'):
                disabled.append(account)
            # blank passwords are bad!
            elif password == "":
                no_password.append(account)
            # otherwise the account has a password
            else:
                passworded.append(account)

    if len(no_password) > 0:
        notes = "Account(s) { " + str(no_password) + " } have no password!"
        test_result = Result.FAIL
    else:
        notes = ("Disabled: " + str(len(disabled)) + ", Locked: " +
                 str(len(locked)) + ", Password: " + str(len(passworded)) +
                 ", No Password: " + str(len(no_password)))
        test_result = Result.PASS

    return TestResult(test_result, notes)


@test_class.tag("system", "config", "users")
@test_class.explanation(
    """
    Sudoers can provide a path for privilege escalation.  It is very important
    to keep close track of which users have sudo privileges.  In particular,
    users which have sudo privilege without requiring a password (NOPASSWD),
    can provide attackers with an easy path to obtain root level access to a
    system.
    """)
def test_accounts_nopassword():
    # WIP - Travis
    pass