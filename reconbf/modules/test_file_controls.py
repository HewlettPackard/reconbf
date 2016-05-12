import os
from reconbf.lib.logger import logger
import reconbf.lib.test_class as test_class
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult
from reconbf.lib import utils

from grp import getgrgid
from pwd import getpwuid


def _conf_test_perms_and_ownership():
    return [{"file": "/etc/inittab",
             "disallowed_perms": "x,rwx,rwx"},
            {"file": "/etc/security/console.perms",
             "disallowed_perms": "x,rwx,rwx"},
            {"file": "/etc/sysctl.conf",
             "disallowed_perms": "x,wx,wx",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/bash.bashrc",
             "disallowed_perms": "x,wx,wx",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/securetty",
             "disallowed_perms": "x,rwx,rwx",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/sudoers",
             "disallowed_perms": "wx,wx,rwx"},
            {"file": "/etc/rsyslog.conf",
             "disallowed_perms": "x,wx,rwx",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/crontab",
             "disallowed_perms": "x,rwx,rwx",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/fstab",
             "disallowed_perms": "x,wx,rwx",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/dpkg",
             "disallowed_perms": ",w,rwx",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/security/access.conf",
             "disallowed_perms": "x,wx,rwx",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/shadow",
             "disallowed_perms": "x,wx,rwx",
             "owner": "root"},
            {"file": "/etc/passwd",
             "disallowed_perms": "x,wx,wx"},
            {"file": "/etc/group",
             "disallowed_perms": "x,wx,wx"},
            {"file": "/root",
             "disallowed_perms": ",rwx,rwx"},
            {"file": "/var/log/auth.log",
             "disallowed_perms": "x,wx,rwx"},
            {"file": "/var/log/dmesg",
             "disallowed_perms": "x,wx,rwx"},
            {"file": "/var/log/wtmp",
             "disallowed_perms": "x,rwx,rwx"},
            {"file": "/var/log/lastlog",
             "disallowed_perms": "x,rwx,rwx"},
            {"file": "/var/spool/cron",
             "disallowed_perms": "x,rwx,rwx"},
            {"file": "/var/spool/cron/root",
             "disallowed_perms": "x,rwx,rwx"},
            {"file": "/etc/gshadow",
             "disallowed_perms": "x,wx,rwx",
             "owner": "root"},
            {"file": "/boot/grub/grub.cfg",
             "disallowed_perms": "x,wx,wx"},
            {"file": "/lib",
             "disallowed_perms": ",w,w"},
            {"file": "/lib64",
             "disallowed_perms": ",w,w"},
            {"file": "/usr/lib",
             "disallowed_perms": ",w,w"},
            {"file": "/usr/lib64",
             "disallowed_perms": ",w,w"},
            {"file": "/etc/rc0.d",
             "disallowed_perms": ",w,w",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/rc1.d",
             "disallowed_perms": ",w,w",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/rc2.d",
             "disallowed_perms": ",w,w",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/rc3.d",
             "disallowed_perms": ",w,w",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/rc4.d",
             "disallowed_perms": ",w,w",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/rc5.d",
             "disallowed_perms": ",w,w",
             "owner": "root",
             "group": "root"},
            {"file": "/etc/rc6.d",
             "disallowed_perms": ",w,w",
             "owner": "root",
             "group": "root"}
            ]


@test_class.takes_config(_conf_test_perms_and_ownership)
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
def test_perms_and_ownership(file_reqs):

    results = GroupTestResult()

    if not file_reqs:
        return TestResult(Result.SKIP, 'Unable to load module config file')

    else:
        for req in file_reqs:

            # if the entry doesn't even contain a file to check, skip it
            if 'file' not in req:
                stats = None
                continue
            else:
                stats = utils.get_stats_on_file(req['file'])

            if stats:
                if 'disallowed_perms' in req:
                    check_name = "Checking perms for: " + req['file']

                    result = _does_perms_meet_req(stats,
                                                  req['disallowed_perms'])
                    if result.result == Result.SKIP:
                        logger.info("Got malformed permission requirement "
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


def _conf_test_perms_files_in_dir():
    return [{"directory": "/root",
             "dir_disallowed_perms": ",,rwx",
             "file_disallowed_perms": ",,rwx",
             "owner": "root"},
            {"directory": "/usr/sbin",
             "dir_disallowed_perms": ",,w",
             "file_disallowed_perms": ",,w"},
            {"directory": "/etc/init.d",
             "file_disallowed_perms": ",,w"}
            ]


@test_class.takes_config(_conf_test_perms_files_in_dir)
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
def test_perms_files_in_dir(dir_list):
    results = GroupTestResult()

    # if we can't find requirements in the file, skip the test
    if not dir_list:
        test_result = Result.SKIP
        reason = 'Unable to load module config file'
        return TestResult(test_result, reason)

    for dir_req in dir_list:

        check_name = "Checking files in: {}".format(dir_req['directory'])

        if 'directory' not in dir_req:
            reason = "Requirement doesn't include directory, skipping"
            cur_result = TestResult(Result.SKIP, reason)
            results.add(check_name, cur_result)

        # get a list of all the files in the directory, including subdirs
        file_list = utils.get_files_list_from_dir(dir_req['directory'],
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
            stats = utils.get_stats_on_file(f)

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
