import json
import logging
import os
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
