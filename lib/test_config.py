import json
import sys
import test_utils

"""
This class is used to manage the main config for RBF.  It should be loaded
in the beginning of the run and then is globally accessible, but specific
values should be retrieved using 'get_config'.

If there are any problems loading the config (it can't be found or the JSON
doesn't parse, we'll exit the program
"""

config = None


class ConfigNotFound(Exception):
        pass


class Config:
    def __init__(self, config_file):
        logger = test_utils.get_logger()

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

    def get_config(self, config_path):
        '''
        Function will return a specified section of json or value
        :param config_path: Path in JSON document to desired bit
        :return: Value or section of data
        '''
        levels = config_path.split('.')

        cur_item = self._config
        for level in levels:
            if level in cur_item:
                cur_item = cur_item[level]
            else:
                logger = test_utils.get_logger()
                logger.error("[-] Unable to get config value: " + config_path)
                raise ConfigNotFound

        return cur_item


