import os
from lib.logger import logger
import lib.test_class as test_class
import lib.test_config as test_config
from lib.test_result import GroupTestResult
from lib.test_result import Result
from lib.test_result import TestResult
import lib.test_utils as test_utils

from grp import getgrgid
from pwd import getpwuid


@test_class.takes_config
@test_class.explanation(
    """
    Protection name: Restrictive file system controls

    Check: Checks files specified in the configuration file and ensures that
    they do not have specified permissions.

    Purpose: In following the principle of least privilege, files should be
    restricted to only allow the bare minimum permissions required to allow
    them to function properly.  The ability for untrusted or less trusted users
    to access and/or modify important files can lead to vulnerabilities such as
    information disclosure and privilege escalation.

    Furthermore, the owner and group must be checked for critical files to
    ensure that permissions function as expected.

    More information about a file's usage and why it is important can usually
    be found online or on resources such as Linux man pages.

    Each file is tested against minimum required permissions.  If additional
    permissions are found the test fails and displays the extra permissions
    found.
    """)
def test_perms_and_ownership(config):

    results = GroupTestResult()

    try:
        config_file = config['config_file']
    except KeyError:
        logger.error("[-] Can't find definition for 'config_file' in module's "
                     "settings, skipping test")
        return TestResult(Result.SKIP, 'Config missing module config file')
    else:
        file_reqs = test_config.get_reqs_from_file(config_file)

    if not file_reqs:
        return TestResult(Result.SKIP, 'Unable to load module config file')

    else:
        for req in file_reqs:

            # if the entry doesn't even contain a file to check, skip it
            if 'file' not in req:
                stats = None
                continue
            else:
                stats = test_utils.get_stats_on_file(req['file'])

            if stats:
                if 'disallowed_perms' in req:
                    check_name = "Checking perms for: " + req['file']

                    result = _does_perms_meet_req(stats,
                                                  req['disallowed_perms'])
                    if result.result == Result.SKIP:
                        logger.info("[-] Got malformed permission requirement "
                                    "{}".format(req['disallowed_perms']))

                    results.add_result(check_name, result)

                if 'owner' in req or 'group' in req:
                    check_name = "Checking owner/group for: " + req['file']

                    owner_string = None
                    group_string = None

                    if 'owner' in req:
                        owner_string = req['owner']
                    if 'group' in req:
                        group_string = req['group']
                    result = _does_owner_group_meet_req(stats,
                                                        owners=owner_string,
                                                        groups=group_string)
                    results.add_result(check_name, result)

            else:
                check_name = "Checking controls for: " + req['file']
                results.add_result(check_name,
                                   TestResult(Result.SKIP,
                                              notes="Couldn't check file"))

    return results


@test_class.takes_config
@test_class.explanation(
    """
    Protection name: Permissions on direcories and files

    Check: All files in the named directory(ies) do not have specified
    level of permissions granted.

    Purpose: For some directories it's very important to validate that all of
    the contained files have file system controls applied.  For example, most
    users on Linux have /usr/sbin in their path, so if a malicious user can
    mess with files in this directory it may have devastating effects on the
    system.  Similarly important directories may include users' home directory,
    certificate directories, and service configuration directories.
    """)
def test_perms_files_in_dir(config):
    results = GroupTestResult()

    # get config file from rbf.cfg, and get requirements list
    try:
        config_file = config['config_file']
    except KeyError:
        logger.error("[-] Can't find definition for 'config_file' in module's "
                     "settings, skipping test")
        test_result = Result.SKIP
        notes = 'Config missing module config file'
        return TestResult(test_result, notes)
    else:
        dir_list = test_config.get_reqs_from_file(config_file)

    # if we can't find requirements in the file, skip the test
    if not dir_list:
        test_result = Result.SKIP
        reason = 'Unable to load module config file'
        return TestResult(test_result, reason)

    for dir_req in dir_list:

        check_name = "Checking files in: {}".format(dir_req['directory'])
        notes = ""

        if 'directory' not in dir_req:
            reason = "Requirement doesn't include directory, skipping"
            cur_result = TestResult(Result.SKIP, reason)
            results.add(check_name, cur_result)

        # get a list of all the files in the directory, including subdirs
        file_list = test_utils.get_files_list_from_dir(dir_req['directory'],
                                                       subdirs=True,
                                                       files_only=False)

        if not file_list:
            reason = "Directory doesn't exist or can't be read"
            cur_result = TestResult(Result.SKIP, reason)
            results.add_result(check_name, cur_result)
            continue

        fail_count = 0
        fail_files = []

        for f in file_list:
            stats = test_utils.get_stats_on_file(f)

            file_req = None
            owner_req = None
            group_req = None

            # if we have a directory and requirements for directories
            if(os.path.isdir(f) and
               'dir_disallowed_perms' in dir_req):
                    file_req = dir_req['dir_disallowed_perms']

            # or we have a file and file requirements...
            elif(os.path.isfile(f) and
                 'file_disallowed_perms' in dir_req):
                    file_req = dir_req['file_disallowed_perms']

            if 'owner' in dir_req:
                owner_req = dir_req['owner']

            if 'group' in dir_req:
                group_req = dir_req['group']

            result_list = []

            if file_req:
                result = _does_perms_meet_req(stats, file_req)
                result_list.append(result.result)

            result = _does_owner_group_meet_req(stats, owner_req, group_req)
            result_list.append(result.result)

            if Result.FAIL in result_list:
                fail_count += 1
                fail_files.append(f)

        if fail_count > 0:
            owner_req = dir_req['owner'] if 'owner' in dir_req else None
            group_req = dir_req['group'] if 'group' in dir_req else None
            dir_perms = (dir_req['dir_disallowed_perms']
                         if 'dir_disallowed_perms' in dir_req else None)
            file_perms = (dir_req['file_disallowed_perms']
                          if 'file_disallowed_perms' in dir_req else None)

            reason = "{} files don't match requirements (".format(fail_count)

            reason += ("file: {} ".format(dir_req['file_disallowed_perms'])
                       if file_perms else "")

            reason += ("dir: {} ".format(dir_req['dir_disallowed_perms'])
                       if dir_perms else "")

            reason += "owner: {} ".format(owner_req) if owner_req else ""

            reason += "group: {} ".format(group_req) if group_req else ""

            reason += "): { " + ", ".join(fail_files) + " }"

            results.add_result(check_name, TestResult(Result.FAIL, reason))
        else:
            results.add_result(check_name, TestResult(Result.PASS))

    return results


def _does_owner_group_meet_req(stats, owners=None, groups=None):
    test_passed = True
    notes = ""

    if owners:
        owners_list = owners.replace(' ', '').split(',')
        file_owner = getpwuid(stats.st_uid).pw_name
        if file_owner not in owners_list:
            test_passed = False
            notes += "owner: " + file_owner

    if groups:
        groups_list = groups.replace(' ', '').split(',')
        file_group = getgrgid(stats.st_gid).gr_name
        if file_group not in groups_list:
            test_passed = False
            if notes != "":
                notes += ", "
            notes += "group: " + file_group

    if not test_passed:
        test_status = Result.FAIL
    else:
        test_status = Result.PASS

    return TestResult(test_status, notes)


def _does_perms_meet_req(stats, disallowed_perms):
    """Checks a files permissions against a permission requirement

    :param stats: Stat object of a file returned by stat
    :param disallowed_perms: A string representing unix style permissions that
    the file should NOT have.

    Example: w,rwx,rwx means that the owner should not have write access and
    all other users and groups should have no access.

    Example: ,,rw means that the file should not have world readable or
    writeable access.

    :returns: A TestResult object containing the result and notes explaining
    why it didn't pass.
    """

    # There's undoubtedly some simple clever binary algebra way to do this
    vals_with = dict()
    vals_with['r'] = [4, 5, 6, 7]
    vals_with['w'] = [2, 3, 6, 7]
    vals_with['x'] = [1, 3, 5, 7]

    # Scopes are User, Group, and World
    scope = ['U', 'G', 'W']

    sections = disallowed_perms.split(',')

    # Sections are the three sections in the disallowed string we are passed,
    # which represent user, group, and world.
    # If we didn't get 3 sections, it's malformed - pass the test with a note
    if len(sections) is not 3:
        return_result = TestResult(Result.SKIP,
                                   notes="Malformed permission req")
    else:
        did_pass = True
        reason = ""
        # Get numeric value for file permissions - eg 644
        file_perms_num = oct(stats.st_mode & 0o777)[-3:]

        cur_pos = 0
        for section in sections:
            cur_perm = file_perms_num[cur_pos]

            # If we're checking for read access and the numeric permission
            # indicates that read access is granted, it's failed... add why to
            # the notes
            if 'r' in section and int(cur_perm) in vals_with['r']:
                did_pass = False
                reason += scope[cur_pos] + ':r '
            # Same for write access...
            if 'w' in section and int(cur_perm) in vals_with['w']:
                did_pass = False
                reason += scope[cur_pos] + ':w '
            # and execute access
            if 'x' in section and int(cur_perm) in vals_with['x']:
                did_pass = False
                reason += scope[cur_pos] + ':x '

            # Next time through the loop look at the next section
            cur_pos += 1

        if did_pass:
            return_result = TestResult(Result.PASS)
        else:
            return_result = TestResult(Result.FAIL, notes=reason)

    return return_result
