import glob
import json
import logging
import os
import subprocess
import test_constants
import test_config
from test_config import ConfigNotFound

"""
This module is where utility functions which are generally useful to tests
should be defined.
"""


class ValNotFound(Exception):
    pass


def check_path_exists(path):
    '''
    Checks for the existence of a path
    :param path: The path to check
    :return: True or False
    '''
    logger = get_logger()
    logger.debug("[*] Testing for existence of path { " + path + " }")

    return_value = os.path.exists(path)
    if return_value:
        logger.debug("[+] Path { " + path + " } exists")
    else:
        logger.debug("[-] Path { " + path + " } doesn't exist")

    return return_value


def get_stats_on_file(file_name):
    '''
    Return the os.stat value for the specified filename, or None if it fails.
    :param file_name: The filename to get stat for
    :return: an os.stat return value
    '''
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
    '''
    Utility function used to find all descendants of a base path
    :param base_path: The main path to start looking from
    :param subdirs: True/False- Recurse through subdirectories?
    :param files_only: True/False- List directories?
    :return:
    '''
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
                do_add = True

                if root != base_path and not subdirs:
                    pass
                else:
                    return_list.append(root + '/' + filename)

            if not files_only:
                for dirname in dirnames:
                    return_list.append(root + '/' + dirname)

    return return_list


def get_logger():
    '''
    Used to get the constant logger
    :return: The logger instance
    '''
    return logging.getLogger(test_constants.logger_name)


def get_reqs_from_file(requirements_file, requirements_id="requirements"):
    '''
    Used to load a JSON file which contains configuration, and return the
    specified object from it
    :param requirements_file: The configuration file to load
    :param requirements_id: The object to look for in the file
    :return: The parsed object from the JSON file
    '''
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
        logger.error("[-] File { " + requirements_file + " } does not appear " +
                     "to be valid JSON.")
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
    '''
    Used to retrieve the value of a sysctl setting.  Uses a configurable
    base sysctl path. Raises a ValNotFound exception if the setting can't
    be retrieved for some reason.
    :param path: The path relative to base sysctl of the setting to retrieve
    :return: The value of the specified sysctl setting
    '''
    logger = get_logger()
    logger.debug("[*] Testing for sysctl value { " + path + " }")

    # load sysctl_path from config if possible, otherwise grab default
    config = test_config.config
    try:
        sysctl_path = config.get_config("paths.sysctl_path")
    except ConfigNotFound:
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
    """
    Use the /proc filesystem to determine a list of running processes.

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
        except OSError as err:
            logger.debug("[*] Unable to locate exe for {" + str(pid) + "}")
        procs.append((pid, exe))

    return procs


def executables_in_path():
    """
    Search the current $PATH to create a list of all executable files.

    :returns: A list of all executables on the $PATH
    """
    logger = get_logger()
    executables = []
    try:
        syspath = os.environ['PATH']
    except KeyError as err:
        logger.debug("[*] $PATH variable not set.")
        return []

    for path in syspath.split(':'):
        for dirname, _, files in os.walk(path):
            executables.extend([os.path.join(path, f) for f in files])

    is_exec = lambda x: os.path.isfile(x) and os.access(x, os.X_OK)
    return [ x for x in executables if is_exec(x) ]


def have_command(cmd):
    """
    Returns true if the specified command is availabe on the system
    path.

    :param cmd: The command to check for using 'which'
    :returns: True if the supplied command is available on the path
    """
    logger = get_logger()
    try:
        null = open(os.devnull, 'w')
        rc = subprocess.check_call(['which', cmd], stdout=null, stderr=null)
        return rc == 0

    except subprocess.CalledProcessError as err:
        logger.debug("[*] {} not on $PATH".format(command))

    return False


def _extract_symbols(cmd):
    """
    Helper function to reduce code duplication. Only difference
    in output of commands comes from the way the 'nm' command
    is run.

    :param cmd: The way to invoke 'nm' command.
    :returns: Generated symbols resulting from nm invocation.
    """
    logger = get_logger()
    try:
        null = open(os.devnull, 'w')
        entries = subprocess.check_output(cmd, stderr=null)
        for entry in entries.split('\n'):
            try:
                values = entry.strip().split(' ')
                # handle case:
                #                  U __sprintf_chk@@GLIBC_2.3.4
                if len(values) == 2:
                    sym_addr = None
                    sym_type, sym_name = values
                # otherwise expect:
                # 00000000004004b0 T main
                else:
                    sym_addr, sym_type, sym_name = entry.split(' ')

                yield (sym_addr, sym_type, sym_name.split('@@')[0])
            except ValueError as err:
                logger.debug('[*] Unexpected output {' + entry.strip() + '}')

    except subprocess.CalledProcessError as err:
        logger.debug(err)


def symbols_in_elf(path):
    """
    Generator to return the symbols within an ELF executable or
    shared library. Output taken from the 'nm' command.

    *NOTE* This will note return any results for stripped binaries.

    :param path: The path of the executable or shared library to extract
                 symbols from.

    :returns: Generator that yields the symbols that are either
              defined in, or referenced by a given ELF file.
    """
    return _extract_symbols(['nm', path])

def symbols_in_dynsym(path):
    """
    Generator to return all the symbols within an ELF executable dynsym
    section. These results will only include the symbols needed for
    dynamic linking at runtime. This section will exists even when the
    binary is stripped.  Essentially this is output taken from `nm -D`

    :param path: The path of the executable to be examined.

    :returns: Generator the yields the symbols in the .dynsym section
              of the ELF binary.
    """
    return _extract_symbols(['nm', '-D', path])


