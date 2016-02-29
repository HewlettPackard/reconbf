from logger import logger
import test_config
import test_constants

from collections import defaultdict
import glob
import os
import subprocess

"""
This module is where utility functions which are generally useful to tests
should be defined.
"""


class ValNotFound(Exception):
    pass


def check_path_exists(path):
    """Checks for the existence of a path

    :param path: The path to check
    :returns: True or False
    """
    logger.debug("[*] Testing for existence of path { " + path + " }")

    return_value = os.path.exists(path)
    if return_value:
        logger.debug("[+] Path [ {} ] exists".format(path))
    else:
        logger.debug("[-] Path [ {} ] doesn't exist".format(path))

    return return_value


def get_stats_on_file(file_name):
    """Return the os.stat value for the specified filename, or None if it
    fails.

    :param file_name: The filename to get stat for
    :returns: an os.stat return value
    """
    logger.debug("[*] Retrieving permission for file [ {} ] ".
                 format(file_name))

    return_value = None
    try:
        return_value = os.stat(file_name)
    except OSError:
        logger.info("[*] Stat for [ {} ] failed".format(file_name))
    else:
        logger.debug("[+] Permissions: {} found for [ {} ]".
                     format(return_value, file_name))
    return return_value


def get_files_list_from_dir(base_path, subdirs=True, files_only=True):
    """Utility function used to find all descendants of a base path

    :param base_path: The main path to start looking from
    :param subdirs: True/False- Recurse through subdirectories?
    :param files_only: True/False- List directories?
    :returns:
    """
    return_list = None

    logger.debug("[*] Listing files from directory [ {} ] ".format(base_path))

    if not check_path_exists(base_path):
        pass
    elif not os.path.isdir(base_path):
        logger.debug("[-] Path [ {} ] is not a directory".format(base_path))
    else:
        # we have a directory, get all the files from it
        return_list = []
        for root, dirnames, filenames in os.walk(base_path):
            for filename in filenames:
                if root != base_path and not subdirs:
                    pass
                else:
                    return_list.append(root + '/' + filename)

            if not files_only:
                for dirname in dirnames:
                    return_list.append(root + '/' + dirname)

    return return_list


def get_sysctl_value(path):
    """Used to retrieve the value of a sysctl setting.  Uses a configurable
    base sysctl path. Raises a ValNotFound exception if the setting can't
    be retrieved for some reason.

    :param path: The path relative to base sysctl of the setting to retrieve
    :returns: The value of the specified sysctl setting
    """
    logger.debug("[*] Testing for sysctl value [ {} ] ".format(path))

    # load sysctl_path from config if possible, otherwise grab default
    config = test_config.config
    try:
        sysctl_path = config.get_config("paths.sysctl_path")
    except test_config.ConfigNotFound:
        sysctl_path = test_constants.sysctl_path

    value = None
    file_path = sysctl_path + "/" + path

    try:
        with open(file_path, 'r') as sysctl_file:
            value = sysctl_file.readline().strip()
    except IOError:
        logger.warning("[-] Sysctl path [ {} ] not found".format(file_path))
        raise ValNotFound
    except EnvironmentError:
        logger.debug("[-] Unable to read sysctl value [ {} ]".
                     format(file_path))
        raise ValNotFound
    else:
        logger.debug("[+] Value found: [ {} ] ".format(value))

    return value


def running_processes():
    """Use the /proc filesystem to determine a list of running processes.

    :returns: A list containing tuples of the pid of a running process
              and the executable file that launched it (if it exists).
    """
    procs = []
    for path in glob.glob('/proc/[0-9]*'):
        pid = int(os.path.basename(path))
        exe = None
        try:
            exe = os.path.realpath('/proc/{}/exe'.format(pid))
        except OSError:
            logger.debug("[*] Unable to locate exe for [ {} ]".format(pid))
        procs.append((pid, exe))

    return procs


def is_service_running(service_name):
    """Use 'service <servicename> status' command to get the status of a
    service

    :returns: Boolean indicating if the service is running
    """

    service_command = ['service', service_name, 'status']
    service_running = False

    run_indicator = 'Active: active (running)'

    try:
        service_status = subprocess.check_output(service_command)

    # service command doesn't exist...
    except OSError:
        logger.error("[-] Unable to call service command")

    except subprocess.CalledProcessError:
        # this indicates service is not running
        pass

    else:
        if run_indicator in service_status:
            service_running = True

    return service_running


def executables_in_path():
    """Search the current $PATH to create a list of all executable files

    :returns: A list of all executables on the $PATH
    """
    executables = []
    try:
        syspath = os.environ['PATH']
    except KeyError:
        logger.debug("[*] $PATH variable not set.")
        return []

    for path in syspath.split(':'):
        for dirname, _, files in os.walk(path):
            executables.extend([os.path.join(path, f) for f in files])

    is_exec = lambda x: os.path.isfile(x) and os.access(x, os.X_OK)
    return [x for x in executables if is_exec(x)]


def config_search(filename, config_descriptor, comment_delims=['#'],
                  keyval_delim=' '):
    """Find the option value specified by config_descriptor in file specified
    by filename.  If the file doesn't exist, will log an error and then
    re-raise the IOError exception.  If the option exists, return it, otherwise
    return None.
    :param filename: The config file to look for the value in
    :param config_descriptor: String in the format 'section_header.value_name'
    :param comment_delims: (optional) list of characters which indicate a
    comment when seen at the beginning of the line

    :param keyval_delim: (optional) character which deliminates a key value
    separation

    :returns: Value of config setting if it exists, otherwise None
    """

    try:
        with open(filename, 'r') as fp:
            config_lines = fp.readlines()

    except IOError:
        logger.error("[-] Unable to read config file: [ {} ] ".
                     format(filename))
        raise IOError

    config_sections = defaultdict(dict)
    current_header = ''

    for line in config_lines:
        # strip spaces from the left, strip newline from the right
        stripped_line = line.lstrip(' ').strip()

        # if this is now an empty line, skip
        if len(stripped_line) < 1:
            pass

        # if this is a comment line, skip
        elif stripped_line[0] in comment_delims:
            pass

        # if this is a header line, set the header
        elif stripped_line[0] == '[':
            right_brace = stripped_line.find(']', 0)
            if right_brace != -1:
                current_header = stripped_line[1:right_brace]

        # otherwise this is a key value line
        else:
            # everything to the left of the keyval delimiter is the key, to
            # the right is the value
            keyval = stripped_line.split(keyval_delim, 1)
            key = keyval[0]

            # if there is no value, it's an empty string
            if len(keyval) > 1:
                value = keyval[1]
            else:
                value = ''

            config_sections[current_header][key] = value

    # search for the option specified in config descriptors
    config_descriptors = config_descriptor.split('.')

    # no section specified, look for the value in the '' section
    if len(config_descriptors) == 1:
        section = ''
        option = config_descriptors[0]

    elif len(config_descriptors) == 2:
        section = config_descriptors[0]
        option = config_descriptors[1]

    else:
        logger.error('[-] Malformed config descriptor: [ {} ]'.
                     format(config_descriptor))
        return None

    try:
        return config_sections[section][option]
    except KeyError:
        return None


def have_command(cmd):
    """Returns true if the specified command is available on the system
    path.

    :param cmd: The command to check for using 'which'
    :returns: True if the supplied command is available on the path
    """
    try:
        null = open(os.devnull, 'w')
        rc = subprocess.check_call(['which', cmd], stdout=null, stderr=null)
        return rc == 0

    except subprocess.CalledProcessError:
        logger.debug("[*] {} not on $PATH".format(cmd))

    return False


def get_flavor():
    """
    Returns the flavor listed in /etc/issue

    :returns: The Linux flavor in item[0] (if Debian/RH derivative)
    """
    try:
        file = open('/etc/issue', 'rb')
        item = file.readline().split()
    except IOError:
        return 'OTHER'
    file.close()

    if 'Debian' in item[0] or 'Ubuntu' in item[0] or 'hLinux' in item[0]:
        return 'DEB'
    elif 'RedHat' in item[0] or 'CentOS' in item[0]:
        return 'RH'
