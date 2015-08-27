import test_utils

import json
import sys

"""
This class is used to manage the main config for RBF.  It should be loaded
in the beginning of the run and then is globally accessible, but specific
values should be retrieved using 'get_config'.

If there are any problems loading the config (it can't be found or the JSON
doesn't parse, we'll exit the program.
"""

config = None


class ConfigNotFound(Exception):
        pass


class Config:
    def __init__(self, config_file):
        logger = test_utils.get_logger()

        # default config search path
        self._config_paths = ['config']

        # try to initialize config class from specified json config file
        try:
            with open(config_file, 'r') as json_file:
                json_data = json.load(json_file)

        except EnvironmentError:
            logger.error("[-] Unable to open config file { " + config_file +
                         " }")
            sys.exit(2)

        except ValueError:
            logger.error("[-] File { " + config_file + " } does not appear "
                         "to be valid JSON.")
            sys.exit(2)

        else:
            self._config = json_data

    def set_profile_config_path(self, profile_config_path):
        # if a profile config path is specified, it takes precedence
        self._config_paths.insert(0, profile_config_path)

    @property
    def config_paths(self):
        return self._config_paths

    def get_config(self, config_path):
        """Function will return a specified section of json or value

        :param config_path: Path in JSON document to desired bit
        :returns: Value or section of data
        """
        levels = config_path.split('.')

        cur_item = self._config
        for level in levels:
            if level in cur_item:
                cur_item = cur_item[level]
            else:
                logger = test_utils.get_logger()
                logger.info("[-] Unable to get config value: " + config_path)
                raise ConfigNotFound

        return cur_item


def get_reqs_from_file(requirements_file, requirements_id="requirements"):
    """Used to load a JSON file which contains configuration, and return the
    specified object from it

    :param requirements_file: The configuration file to load
    :param requirements_id: The object to look for in the file
    :returns: The parsed object from the JSON file
    """
    logger = test_utils.get_logger()
    logger.debug("[*] Attempting to load " + requirements_id + " from { " +
                 requirements_file + " } .")

    paths = config.config_paths

    for path in paths:
        logger.debug("[*] Trying to read module config file " +
                     requirements_file + " from path " + path)
        try:
            with open(path + "/" + requirements_file, 'r') as json_file:
                json_data = json.load(json_file)

        except EnvironmentError:
            # we couldn't find the file, maybe next path has it
            # if we can't get it by the end, we'll log it
            pass

        except ValueError:
            # if we got bad JSON, log the error and return None
            logger.error("[-] File { " + requirements_file + " } does not " +
                         "appear to be valid JSON.")
            return None

        else:
            # ok, we were able to parse JSON, is requirement in it?
            if requirements_id in json_data:
                logger.debug("[+] Config " + requirements_id + " found in " +
                             "path: " + path)
                return json_data[requirements_id]
            else:
                logger.info("[-] File found but doesn't contain {}.",
                            requirements_id)
                return []

    logger.error("[-] Unable to open file { " + requirements_file +
                 " } for reading!")
    return None
