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
from . import config
from .result import TestResults, TestResult, Result, GroupTestResult
from .. import modules

import importlib
from inspect import getmembers
from inspect import isfunction
import pkgutil
import sys

"""
This module implements the TestSet class which is responsible for discovering,
maintaining, and running a set of tests.

For each test we will store:
 - the function name, as declared in the Python module
 - the function itself, this is the code that will be executed for the test
 - the module name that the function came from

A typical workflow will be:
  1) Load tests into the class with add_from_directory
  2) Optionally prune the tests with methods like set_script
  3) Run the tests which are left after pruning
"""


class SortType:
    def __init__(self):
        pass

    # Used for indicating the way discovered tests should be sorted
    MODULE_ALPHABETIC = 1


class TestSet():
    def __init__(self, copy_set=None):
        # tests is a list of test functions
        self._tests = list()
        if copy_set:
            self._tests = copy_set.tests

    @property
    def count(self):
        return len(self._tests)

    @property
    def tests(self):
        return self._tests

    def add_known_tests(self, configured_modules=None):
        """Adds all known recon tests to the test set.
        """

        orig_count = self.count

        test_list = []

        for _loader, module_name, _ispkg in pkgutil.iter_modules(
                modules.__path__):
            logger.debug("Importing tests module: %s", module_name)

            if configured_modules is not None and \
                    module_name not in configured_modules:
                logger.debug("Module not configured: %s", module_name)
                continue

            # try to import the module by name
            try:
                module = importlib.import_module(
                    modules.__name__ + "." + module_name)

            # if it fails, die
            except ImportError:
                logger.exception("Could not import test module '%s'",
                                 modules.__name__ + "." + module_name)
                sys.exit(2)

            # otherwise we want to obtain a list of all functions in the module
            # and add them to our dictionary of tests
            for fn_name, function in getmembers(module):
                if not isfunction(function):
                    continue
                if not hasattr(function, "is_recon_test"):
                    continue

                new_test = {
                    'name': fn_name,
                    'function': function,
                    'module': module_name,
                    }
                test_list.append(new_test)

        self._tests += _sort_tests(test_list, SortType.MODULE_ALPHABETIC)

        # return the number of test cases added
        return self.count - orig_count

    def run(self):
        """Run all tests in this TestSet and return results

        :returns: Tuple containing qualified test name and result
        """
        results = list()

        for test in self._tests:
            cur_result = dict()

            test_name = "%s.%s" % (test['module'], test['name'])
            test_result = None

            fn = test['function']

            # if a function takes config, pass it the data for it
            if hasattr(fn, 'takes_config') and config:
                try:
                    conf = config.get_config('modules.' + test_name)
                except config.ConfigNotFound:
                    logger.error("Test [ %s ] requires config but could "
                                 "not be found.  Skipping...",
                                 test_name)
                else:
                    # if the config is not available, use defaults
                    if conf is None and fn.config_generator is not None:
                        conf = fn.config_generator()

                    try:
                        test_result = fn(conf)
                    # catch anything that goes wrong with a test
                    except Exception:
                        logger.exception("Exception in test [ %s ]", test_name)

            else:
                try:
                    test_result = fn()
                # catch anything that goes wrong with a test
                except Exception:
                    logger.exception("Exception in test [ %s ]", test_name)

            # Name and result class are added
            cur_result = {'name': test_name}

            # If the test actually ran...
            if test_result is None:
                cur_result['result'] = TestResult(
                    Result.FAIL, "Test did not return result, internal error")
            elif isinstance(test_result, TestResult):
                # single result can be added to the list
                cur_result['result'] = test_result
            elif isinstance(test_result, GroupTestResult):
                # if the group contains no results, report a skip
                if len(test_result) == 0:
                    cur_result['result'] = TestResult(
                        Result.SKIP, "No specific results reported")
                else:
                    cur_result['result'] = test_result
            else:
                # if the test either failed or never returned a result, make
                # sure that's reported too
                cur_result['result'] = TestResult(
                    Result.FAIL, "Test failed to run, internal error")
            results.append(cur_result)

        return TestResults(results)

    def set_script(self, script_file):
        """This method takes a script file, and sets the test set to run specified
        tests in the order listed in the script.

        :param script_file: File to use for script
        :returns: -
        """

        script_lines = []
        new_test_set = []

        try:
            script_f = open(script_file, 'r')
            script_lines = script_f.readlines()
            script_f.close()

        except IOError:
            logger.error("Unable to open script file [ %s ]", script_file)
            return False

        else:
            for line in script_lines:
                # for each line in the script, find the appropriate test
                # and add it
                test = self._find_test_by_can_name(line.strip())
                if not test:
                    logger.error("Unable to find test: [ %s ]", line.strip())
                    sys.exit(2)
                new_test_set.append(test)

        logger.info("Loaded script [ %s ]", script_file)
        self._tests = new_test_set
        return True

    def _find_test_by_can_name(self, module_str):
        """Find a test by it's canonical name: module name + '.' + test name

        :returns: The test dictionary for specified test
        """

        # module name is the part before the . , test name is the part after
        module_ids = module_str.split('.')

        # if we don't have a well-formed canonical name, don't try to find it
        if len(module_ids) != 2:
            logger.error("Malformed script line: [ %s ]", module_str)
            return None

        for test in self._tests:
            if(test['module'] == module_ids[0] and
                    test['name'] == module_ids[1]):
                return test
        return None


def _sort_tests(sort_list, sort_type):
    sorted_list = []

    # other sort types might be supported in the future...
    if sort_type == SortType.MODULE_ALPHABETIC:
        # sorting module alphabetic sorts according to module name first, then
        # function name
        sorted_list = sorted(sort_list,
                             key=lambda test_name: test_name['module'] +
                             '.' + test_name['name'])

    return sorted_list


def explanation(exp):
    """Decorator to add an explanation for why a test is important from a
    security perspective

    :param exp: String explanation of the test
    :returns: Function which contains the "explanation" attribute
    """
    def decorate(f):
        f.explanation = exp
        f.is_recon_test = True
        return f
    return decorate


def takes_config(conf_gen_func=None):
    """Decorator to indicate that function takes a config dictionary

    Example:
        @takes_config(config_generator)
        def test_xyz(self):

    :returns: Function which contains the has "takes_config" attribute
    """
    def decorate(func):
        # Just having the attribute indicates that it takes config, no value
        # needed
        func.takes_config = None
        func.config_generator = conf_gen_func
        return func
    return decorate
