import test_config
import test_constants

import ConfigParser
import StringIO
import glob
import json
import logging
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
    logger = get_logger()
    logger.debug("[*] Testing for existence of path { " + path + " }")

    return_value = os.path.exists(path)
    if return_value:
        logger.debug("[+] Path { " + path + " } exists")
    else:
        logger.debug("[-] Path { " + path + " } doesn't exist")

    return return_value


def get_stats_on_file(file_name):
    """Return the os.stat value for the specified filename, or None if it
    fails.

    :param file_name: The filename to get stat for
    :returns: an os.stat return value
    """
    logger = get_logger()
    logger.debug("[*] Retrieving permission for file { " + file_name + "}")

    return_value = None
    try:
        return_value = os.stat(file_name)
    except OSError:
        logger.info("[*] Stat for { " + file_name + " } failed")
    else:
        logger.debug("[+] Permissions: " + str(return_value) + " found for " +
                     "{ " + file_name + " }")
    return return_value


def get_files_list_from_dir(base_path, subdirs=True, files_only=True):
    """Utility function used to find all descendants of a base path

    :param base_path: The main path to start looking from
    :param subdirs: True/False- Recurse through subdirectories?
    :param files_only: True/False- List directories?
    :returns:
    """
    return_list = None

    logger = get_logger()
    logger.debug("[*] Listing files from directory { " + base_path + " }")

    if not check_path_exists(base_path):
        pass
    elif not os.path.isdir(base_path):
        logger.debug("[-] Path { " + base_path + " } is not a directory")
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


def get_logger():
    """Used to get the constant logger

    :returns: The logger instance
    """
    return logging.getLogger(test_constants.logger_name)


def get_reqs_from_file(requirements_file, requirements_id="requirements"):
    """Used to load a JSON file which contains configuration, and return the
    specified object from it

    :param requirements_file: The configuration file to load
    :param requirements_id: The object to look for in the file
    :returns: The parsed object from the JSON file
    """
    logger = get_logger()
    return_value = None

    logger.debug("[*] Attempting to load " + requirements_id + " from { " +
                 requirements_file + " } .")

    try:
        with open(requirements_file, 'r') as json_file:
            json_data = json.load(json_file)

    except EnvironmentError:
        logger.error("[-] Unable to open file { " +
                     requirements_file + " } for reading!")
        raise EnvironmentError
    except ValueError:
        logger.error("[-] File { " + requirements_file + " } does not " +
                     "appear to be valid JSON.")
        raise ValueError
    else:
        if requirements_id in json_data:
            logger.debug("[+] {} found.", requirements_id)
            return_value = json_data['requirements']
        else:
            logger.info("[-] File found but doesn't contain {}.",
                        requirements_id)
            return_value = []
    return return_value


def get_sysctl_value(path):
    """Used to retrieve the value of a sysctl setting.  Uses a configurable
    base sysctl path. Raises a ValNotFound exception if the setting can't
    be retrieved for some reason.

    :param path: The path relative to base sysctl of the setting to retrieve
    :returns: The value of the specified sysctl setting
    """
    logger = get_logger()
    logger.debug("[*] Testing for sysctl value { " + path + " }")

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
        logger.warning("[-] Sysctl path { " + file_path + " } not found")
        raise ValNotFound
    except EnvironmentError:
        logger.debug("[-] Unable to read sysctl value { " + file_path + " }")
        raise ValNotFound
    else:
        logger.debug("[+] Value found: { " + value + " }")

    return value


def running_processes():
    """Use the /proc filesystem to determine a list of running processes.

    :returns: A list containing tuples of the pid of a running process
              and the executable file that launched it (if it exists).
    """
    logger = get_logger()
    procs = []
    for path in glob.glob('/proc/[0-9]*'):
        pid = int(os.path.basename(path))
        exe = None
        try:
            exe = os.path.realpath('/proc/{}/exe'.format(pid))
        except OSError:
            logger.debug("[*] Unable to locate exe for {" + str(pid) + "}")
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
        get_logger().error("[-] Unable to call service command")

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
    logger = get_logger()
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


def config_search(filename, config_descriptor):
    """Find the option value specified by config_descriptor in file specified
    by filename.  If the file doesn't exist, will log an error and then
    re-raise the IOError exception.  If the option exists, return it, otherwise
    return None.
    :param filename: The config file to look for the value in
    :param config_descriptor: String in the format 'section_header.value_name'
    :returns: Value of config setting if it exists, otherwise None
    """
    # if the config file passed doesn't exist, return an exception
    if not check_path_exists(filename) or not os.access(filename, os.R_OK):
        get_logger().error("[-] Can't open config file: { " + filename + " }")
        # raise the IOError exception so that calling functions can detect that
        # the file didn't exist
        raise IOError

    # try to parse the config file normally
    try:
        parser = ConfigParser.SafeConfigParser(allow_no_value=True)
        parser.read(filename)

    # if the config file didn't have sections, ConfigParser gets upset, so we
    # need a workaround...
    except ConfigParser.MissingSectionHeaderError:
        # we're going to create a new version of the file in memory, with a
        # section called [dummy] at the top
        modified_file = StringIO.StringIO()
        modified_file.write('[dummy]\n')

        with open(filename, 'r') as cfg_file:
            modified_file.write(cfg_file.read())
            cfg_file.close()

            # rewind to the beginning of the file
            modified_file.seek(0)

            # then attempt to parse the modified file
            try:
                parser.readfp(modified_file)
            except ConfigParser.ParsingError:
                get_logger().error("[-] Improperly formatted config file: { " +
                                   filename + " }")
                return None

    except ConfigParser.ParsingError:
        get_logger().error("[-] Improperly formatted config file: { " +
                           filename + " }")
        return None

    num_descriptors = len(config_descriptor.split('.'))

    # if one descriptor was passed, we'll assume the option isn't in a config
    # section, and therefore it should have been placed in the [dummy] section
    if num_descriptors == 1:
        section_name = "dummy"
        option_name = config_descriptor

    # otherwise, the bit before the '.' is the section name, and the bit after
    # is the option name
    elif num_descriptors == 2:
        section_name = config_descriptor.split('.')[0]
        option_name = config_descriptor.split('.')[1]

    # if there aren't the right number of sections, error out and return None
    else:
        get_logger().error("[-] Improperly formatted config option: { " +
                           config_descriptor + " }")
        return None

    # this will work if the key/value is delimited with an '=' as ConfigParser
    # assumes
    if parser.has_option(section_name, option_name):
        return parser.get(section_name, option_name)

    # otherwise we need to parse the options manually
    try:
        options = parser.options(section_name)

    # if we don't find it, return None
    except ConfigParser.NoSectionError:
        return None

    # for each option listed in the section, separate the option name (part
    # before the first space) from the option value (part after the first
    # space)
    else:
        for option in options:
            try:
                if option.split(' ', 1)[0] == option_name:
                    return option.split(' ', 1)[1]
            except IndexError:
                return ""

    return None


def have_command(cmd):
    """Returns true if the specified command is available on the system
    path.

    :param cmd: The command to check for using 'which'
    :returns: True if the supplied command is available on the path
    """
    logger = get_logger()
    try:
        null = open(os.devnull, 'w')
        rc = subprocess.check_call(['which', cmd], stdout=null, stderr=null)
        return rc == 0

    except subprocess.CalledProcessError:
        logger.debug("[*] {} not on $PATH".format(cmd))

    return False
