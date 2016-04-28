from reconbf.lib.logger import logger
import reconbf.lib.test_class as test_class
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult

try:
    import grp
    import pwd

    import spwd
except ImportError as e:
    logger.error("[-] Error importing module: {}".format(e))

from collections import defaultdict
import subprocess


@test_class.explanation(
    """
    Protection name: Accounts with no password

    Check: Lists how many accounts are lockerd, disabled, and have no password
    set.  Will fail for, and list, any accounts which are found with no
    password.

    Purpose: Every user account should either have a password set or be
    disabled. One common way for attackers to gain access to a system is to
    enumerate typical user accounts and try to log in with usual credentials,
    or even without credentials.  By ensuring all accounts have passwords or
    are disabled, it makes it harder for an attacker to gain a foothold in the
    system.
    """)
def test_accounts_nopassword():
    disabled = []
    locked = []
    passworded = []
    no_password = []

    shadow_entries = spwd.getspall()

    for entry in shadow_entries:
        # passwords which start with ! have been locked
        if entry.sp_pwd.startswith('!'):
            locked.append(entry.sp_nam)
        # passwords which start with * have been disabled
        elif entry.sp_pwd.startswith('*'):
            disabled.append(entry.sp_nam)
        # blank passwords are bad!
        elif entry.sp_pwd == "":
            no_password.append(entry.sp_nam)
        # otherwise the account has a password
        else:
            passworded.append(entry.sp_nam)

    if len(no_password) > 0:
        notes = "Account(s) { " + str(no_password) + " } have no password!"
        test_result = Result.FAIL
    else:
        notes = ("Disabled: " + str(len(disabled)) + ", Locked: " +
                 str(len(locked)) + ", Password: " + str(len(passworded)) +
                 ", No Password: " + str(len(no_password)))
        test_result = Result.PASS

    return TestResult(test_result, notes)


@test_class.explanation(
    """
    Protection name: List sudoers

    Check: Lists all users that are lister in sudoers.  Fail if any of the
    users have sudo access with NOPASSWD.

    Purpose: Sudoers can provide a path for privilege escalation.  It is very
    important to keep close track of which users have sudo privileges.  In
    particular, users which have sudo privilege without requiring a password
    (NOPASSWD), can provide attackers with an easy path to obtain root level
    access to a system.
    """)
def test_list_sudoers():
    # these can be moved to config if there is a good reason somebody would
    # ever want to change them, for now they stay here
    list_sudoer_command = ['sudo', '-U', '$USER', '-l']

    not_sudo_string = b'not allowed to run sudo'
    sudo_string = b'may run the following commands'
    nopasswd_string = b'NOPASSWD'

    passwd_entries = pwd.getpwall()

    user_accounts = []
    for entry in passwd_entries:
        if entry.pw_name != 'root':
            user_accounts.append(entry.pw_name)

    sudo_users = []
    nopasswd_users = []

    for user in user_accounts:
        # set the user in the sudo command template
        list_sudoer_command[2] = user
        proc = subprocess.Popen(list_sudoer_command, stdout=subprocess.PIPE)
        (output, _stderr) = proc.communicate()

        # if the output has the non-sudo user string in it, do nothing
        if not_sudo_string in output:
            pass
        # otherwise...
        elif sudo_string in output:
            # if NOPASSWD tag is found
            if nopasswd_string in output:
                nopasswd_users.append(user)
            # sudo user that requires a password
            else:
                sudo_users.append(user)

    # fail if there are NOPASSWD sudo users
    if len(nopasswd_users) > 0:
        result = Result.FAIL
        notes = "User(s) { " + str(nopasswd_users) + " } have password-less "
        notes += "sudo access!"
    # otherwise the test passes
    else:
        result = Result.PASS
        if len(sudo_users) > 0:
            notes = "User(s) { " + str(sudo_users) + " } have sudo access"
        else:
            notes = "No users have sudo access"

    return TestResult(result, notes)


@test_class.explanation(
    """
    Protection name: Unique user names and IDs

    Check: The user name (1st item in each passwd entry), and the user ID
    (3rd item in each passwd entry) are unique (don't appear anywhere else in
    the /etc/passwd file).

    Purpose: Users in *nix systems are identified within the system by user ID
    (UID).  These should be unique for each user to prevent unintended
    consequences, such as granting access to a resource for an unexpected user.
    It is particularly important that the root user is the only user on the
    system with UID 0.
    """)
def test_unique_user():
    passwd_entries = pwd.getpwall()
    uids = defaultdict(list)
    user_names = defaultdict(list)

    # create dict of user IDs for user names and user names for user IDs
    for entry in passwd_entries:
        # add the user to the list of users for that UID
        uids[entry.pw_uid].append(entry.pw_name)

        # add the user to the list of UIDs for that username
        user_names[entry.pw_name].append(entry.pw_uid)

    notes = ''
    result = Result.PASS

    # ensure UID is unique, fail if UID 0 is not
    for uid in uids.keys():
        # if there are more than one user with this UID
        if len(uids[uid]) > 1:
            # if the duplicated UID is for root, the test fails
            if uid == 0:
                result = Result.FAIL
            if notes != '':
                notes += ', '
            # regardless, add to the notes that there are multiple users with
            # this UID
            notes += 'Users { ' + str(uids[uid]) + " } have UID " + str(uid)

    # ensure username is unique, fail if root is not
    for username in user_names.keys():
        # if there are more than one user with this user name
        if len(user_names[username]) > 1:
            # if the duplicated user name is root, the test fails
            if username == 'root':
                result = Result.FAIL
            if notes != '':
                notes += ', '
            # regardless, add to the notes that there are multiple users with
            # this name
            notes += 'UIDs { ' + str(user_names[username]) + " } have name "
            notes += username

    if notes == '':
        notes = "No users have same UID or name"

    return TestResult(result, notes)


@test_class.explanation(
    """
    Protection name: Unique group names and IDs

    Check: The group name (1st item in each group entry), and the group ID
    (3rd item in each group entry) are unique (don't appear anywhere else in
    the /etc/group file).

    Purpose: Groups in *nix systems are identified within the system by the
    Group ID (GID).  They are identified by their group name by end users.  To
    avoid granting access to unintended groups, both the group name and group
    ID should be unique for each group.
    """)
def test_unique_group():
    grp_entries = grp.getgrall()
    gids = defaultdict(list)
    group_names = defaultdict(list)

    # create dict of group IDs for group names and group names for group IDs
    for entry in grp_entries:
        # add the group to the list of groups for that GID
        gids[entry.gr_gid].append(entry.gr_name)

        # add the group to the list of GIDs for that group
        group_names[entry.gr_name].append(entry.gr_gid)

    notes = ''
    result = Result.PASS

    # ensure GID is unique, fail if GID 0 is not
    for gid in gids.keys():
        # if there are more than one group with this GID
        if len(gids[gid]) > 1:
            # if the duplicated GID is for root, the test fails
            if gid == 0:
                result = Result.FAIL
            if notes != '':
                notes += ', '
            # regardless, add to the notes that there are multiple groups with
            # this GID
            notes += 'Groups { ' + str(gids[gid]) + " } have GID " + str(gid)

    # ensure group is unique, fail if root is not
    for groupname in group_names.keys():
        # if there are more than one group with this group name
        if len(group_names[groupname]) > 1:
            # if the duplicated group name is root, the test fails
            if groupname == 'root':
                result = Result.FAIL
            if notes != '':
                notes += ', '
            # regardless, add to the notes that there are multiple groups with
            # this name
            notes += 'GIDs { ' + str(group_names[groupname]) + " } have name "
            notes += groupname

    if notes == '':
        notes = "No groups have same GID or name"

    return TestResult(result, notes)
