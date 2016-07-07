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

from reconbf.lib import test_class
from reconbf.lib import utils
from reconbf.lib.result import GroupTestResult, TestResult, Result

import os


CONFIG_PATH = "/etc/mysql/mysql.cnf"
INCLUDE_DIR_MARK = "!includedir "
INCLUDE_FILE_MARK = "!include "


def _get_incdir_config(path):
    included = []
    confs = [conf for conf in os.listdir(path) if conf.endswith('.cnf')]
    # there's no guarantee about the processing order, so just assume the user
    # makes reasonable choices here
    for conf in confs:
        inc_path = os.path.join(path, conf)
        included.extend(_get_full_config(inc_path))
    return included


def _get_full_config(path):
    with open(path, 'r') as conf:
        conf_lines = conf.readlines()

    complete = []
    for line in conf_lines:
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith(";"):
            # not necessary, but skipping comments will save some memory
            continue

        if stripped.startswith(INCLUDE_DIR_MARK):
            inc_path = stripped[len(INCLUDE_DIR_MARK):].strip()
            if not os.path.isabs(inc_path):
                inc_path = os.path.join(os.path.dirname(path), inc_path)
            complete.extend(_get_incdir_config(inc_path))
            continue

        if stripped.startswith(INCLUDE_FILE_MARK):
            inc_path = stripped[len(INCLUDE_FILE_MARK):].strip()
            if not os.path.isabs(inc_path):
                inc_path = os.path.join(os.path.dirname(path), inc_path)
            complete.extend(_get_full_config(inc_path))
            continue

        complete.append(line)

    return complete


def _mysqld_default_config():
    return {
        "mysqld.allow-suspicious-udfs": {"disallowed": ["1"]},
        "mysqld.safe-user-create": {"allowed": ["1", ""]},
        "mysqld.secure-auth": {"disallowed": ["0"]},
        "mysqld.skip-secure-auth": {"disallowed": "*"},
        "mysqld.skip-grant-tables": {"disallowed": "*"},
        "mysqld.skip-show-database": {"allowed": ["1"]},
        }


@test_class.takes_config(_mysqld_default_config)
@test_class.explanation(
    """
    Protection name: Secure mysql configuration

    Check: Validates the security options in mysql configuration.

    Purpose: The following options are included by default:
    - allow-suspicious-udfs: prevents loading and use of unexpected functions
    - safe-user-create: extra protection on user grants manipulation
    - secure-auth: disable old authentication methods
    - skip-grant-tables: ensure authentication is applied
    - skip-show-database: in production there's no reason to discover databases
    """)
def safe_config(expected_config):
    if not os.path.exists(CONFIG_PATH):
        return TestResult(Result.SKIP, "MySQL config not found")

    try:
        config_lines = _get_full_config(CONFIG_PATH)
    except IOError:
        return TestResult(Result.FAIL, "MySQL config could not be read")
    results = GroupTestResult()
    for test, res in utils.verify_config(
            CONFIG_PATH, config_lines, expected_config, keyval_delim='='):
        results.add_result(test, res)
    return results
