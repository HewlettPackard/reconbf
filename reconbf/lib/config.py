# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
        # try to initialize config class from specified json config file
        try:
            json_data = json.load(config_file)

        except ValueError:
            logger.error("File [ %s ] does not appear to be valid JSON.",
                         config_file)
            sys.exit(2)

        else:
            self._config = json_data

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

    def get_configured_tests(self):
        """Return the dict of (module, test_names) for each configured test"""
        tests = {}
        for mod, m_tests in self._config.get('modules', {}).items():
            tests[mod] = list(m_tests)

        return tests


def get_config(config_path, default=_no_default):
    return config.get_config(config_path, default)


def get_configured_tests():
    return config.get_configured_tests()
