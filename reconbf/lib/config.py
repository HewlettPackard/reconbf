from .logger import logger

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


_no_default = object()


class ConfigNotFound(Exception):
        pass


class Config:
    def __init__(self, config_file):

        # default config search path
        self._config_paths = ['config']

        # try to initialize config class from specified json config file
        try:
            with open(config_file, 'r') as json_file:
                json_data = json.load(json_file)

        except EnvironmentError:
            logger.error("Unable to open config file [ %s ]", config_file)
            sys.exit(2)

        except ValueError:
            logger.error("File [ %s ] does not appear to be valid JSON.",
                         config_file)
            sys.exit(2)

        else:
            self._config = json_data

    def set_profile_config_path(self, profile_config_path):
        # if a profile config path is specified, it takes precedence
        self._config_paths.insert(0, profile_config_path)

    @property
    def config_paths(self):
        return self._config_paths

    def get_config(self, config_path, default=_no_default):
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
                if default is _no_default:
                    logger.info("Unable to get config value: %s", config_path)
                    raise ConfigNotFound()
                else:
                    return default

        return cur_item

    def get_configured_modules(self):
        return list(self._config.get('modules', {}).keys())


def get_config(config_path, default=_no_default):
    return config.get_config(config_path, default)


def get_configured_modules():
    return config.get_configured_modules()
