import json
import test_constants
import test_config
from test_config import ConfigNotFound
import test_utils

"""
Several classes are defined in this module:

Result:
    This is used for setting a descriptive value of the outcome of a test.

    This class is basically an ENUM which allows readable values for test
    results.


ResultDisplayType:
    This is used for setting how a test's results should be output.  For
    example in most cases it's probably fine to only show only tests which
    fail.  In some cases though, you'll want to see which tests were skipped
    and why.

    This class is basically an ENUM which allows more nicely readable values
    for this option.


TestResults:
    An instance of this class is returned as the result of a run of a test set.

    TestResults is a list of test run dictionaries, each contains:
    - name: a descriptive name of the test
    - result: either a TestResult or GroupTestResult instance

    Once this class has been instantiated it can be used to display the results
    on the command line or output reports.


TestResult:
    This class represents an individual test result. It contains two values:

    result - This is an item of type Result which indicates the pass status of
        the test that ran
    notes - This is an optional text string field which describes any remarks
        that the test added. This is typically used to indicate reasons why a
        test failed or was skipped.


GroupTestResult:
    Some types of tests test the same thing repeatedly. Rather than list each
    as a separate test they can be defined as a GroupTest which returns results
    as a GroupTestResult. A GroupTestResult is a list of individual tests which
    were run as part of the group. For each sub-test the following is stored:

    - name: a descriptive name of the test
    - result: a TestResult instance

"""


class Result:
    def __init__(self):
        pass

    # Used for indicating the result of a test
    PASS = 1
    FAIL = 2
    SKIP = 3


class ResultDisplayType:
    def __init__(self):
        pass

    # Used for indicating how to display/report test results
    DISPLAY_ALL = 1           # Displays each test
    DISPLAY_FAIL_ONLY = 2     # Displays each failed test and overall
    DISPLAY_NOT_PASS = 3      # Displays each test which isn't pass (fail/skip)
    DISPLAY_OVERALL_ONLY = 4  # Displays only overall result (skip group items)


class TestResults:
    def __init__(self, results_list):
        # Results list is a list of TestResult and GroupTestResult instances
        self._results = results_list

    def add_results(self, new_results):
        '''
        Used for adding a list of one or more TestResult or GroupTestResult
        instances to the set.
        :param new_results: A list of items to append to the list
        :return: None
        '''
        for result in new_results:
            self._results.append(result)

    def display_on_terminal(self, use_color=True,
                            display_type=ResultDisplayType.DISPLAY_NOT_PASS):
        '''
        Pretty display of results on terminal
        :param use_color: (Optional) Boolean indicating whether to use color
        :param display_type: (Optional) ResultDisplayType indicating which
        results to display.
        :return: -
        '''

        term_colors = _get_term_colors()

        # TODO: add some way of specifying a wider terminal
        # Print header section
        print '\n'
        print '=' * 80
        print('{0: <60}'.format('Test Name') + '{0: <10}'.format('Result') +
              'Notes')
        print '=' * 80

        for cur_result in self._results:
            if isinstance(cur_result['result'], TestResult):
                # Handle single result case

                # decide whether to display, based on mode
                if (_check_display_result(cur_result['result'].result,
                                          display_type)
                        or display_type == ResultDisplayType.DISPLAY_OVERALL_ONLY):

                    result_string = _build_result_string(cur_result['name'],
                                                         cur_result['result'].result,
                                                         cur_result['result'].notes,
                                                         use_color, term_colors,
                                                         False)
                    print result_string

            elif isinstance(cur_result['result'], GroupTestResult):
                # if this is a group test, we'll have to determine if the test
                # passed or failed overall
                parent_pass = True
                parent_name = cur_result['name']
                group_result_list = cur_result['result'].results

                child_result_strings = list()

                for result_item in group_result_list:
                    # Determine if we should display this test based on the
                    # ResultDisplayType selected
                    if (_check_display_result(result_item['result'].result,
                                              display_type)
                            and display_type != ResultDisplayType.DISPLAY_OVERALL_ONLY):

                        res = result_item['result']
                        result_string = _build_result_string(result_item['name'],
                                                             res.result,
                                                             res.notes,
                                                             use_color,
                                                             term_colors,
                                                             True)

                        child_result_strings.append(result_string)
                    # Note: Skips don't cause parent to fail
                    if result_item['result'].result == Result.FAIL:
                        parent_pass = False

                if parent_pass:
                    if len(group_result_list) > 0:
                        parent_result = Result.PASS
                    # if no tests were actually run, eg. the test had a problem
                    else:
                        parent_result = Result.SKIP
                else:
                    parent_result = Result.FAIL

                # this is a little complicated, but basically we need to check
                # for three conditions: 1) normal display conditions,
                # 2) if we're displaying overall, always display parent status,
                # 3) if we're showing all not-passes and one of the children was
                # a non-pass, then display the parent
                if (_check_display_result(parent_result, display_type) or
                        display_type == ResultDisplayType.DISPLAY_OVERALL_ONLY or
                        (display_type == ResultDisplayType.DISPLAY_NOT_PASS and
                             len(child_result_strings) > 0)):

                    result_string = _build_result_string(parent_name,
                                                         parent_result, "",
                                                         use_color, term_colors,
                                                         False)

                    print result_string

                for child_string in child_result_strings:
                    print child_string

        print '\n'

    def write_csv(self, filename, separator_char=test_constants.csv_separator):
        '''
        Create a CSV file in the specified location with an optionally
        specified separator, default: '|'

        The fields are test name, result, and notes

        Results will be output in the order errors, then failures,
        and finally successes(?)

        :param filename: The file to write
        :param separator_char: (optional) Separator character for fields
        :return: -
        '''
        logger = test_utils.get_logger()
        logger.info("[*] Preparing to write CSV file { " + filename + " }")

        # TODO: Fix write CSV to reflect new results list structure

        # Create the header row
        header_row_items = ['Test', 'Result', 'Notes']
        header_row = separator_char.join(map(str, header_row_items))

        rows = list()

        # display any errors first

        for test_result in self._results:
            cur_row = list()
            cur_row.append(test_result['name'])
            cur_row.append(test_result['result'])
            if 'notes' in test_result:
                cur_row.append(test_result['notes'])
            else:
                cur_row.append("")
            rows.append(cur_row)

        try:
            with open(filename, 'w') as csv_output:
                csv_output.write(header_row + "\n")
                for row in rows:
                    line = separator_char.join(map(str, row))
                    csv_output.write(line + "\n")

        except EnvironmentError:
            logger.info("[-] Unable to open CSV file { " + filename + " } "
                        + "for writing!")
        else:
            logger.info("[+] Writing CSV file: { " + filename + " } "
                        + "successful!")

    def write_json(self, filename):
        '''
        Create a JSON file in the specified location

        The fields are test name, result, and notes if they exist

        :param filename:
        :return: -
        '''
        logger = test_utils.get_logger()
        logger.info("[*] Preparing to write JSON file { " + filename + " }")

        # Get the test results into an object format that can be serialized
        tests = []
        for test in self._results:
            cur_test = dict()
            cur_test['name'] = test['name']
            if isinstance(test['result'], TestResult):
                cur_test['result'] = _result_text(test['result'].result)
                cur_test['notes'] = test['result'].notes
                tests.append(cur_test)
            elif isinstance(test['result'], GroupTestResult):
                results = []
                for ind_result in test['result'].results:
                    cur_result = dict()
                    cur_result['name'] = ind_result['name']
                    cur_result['result'] = _result_text(
                        ind_result['result'].result)

                    cur_result['notes'] = ind_result['result'].notes
                    results.append(cur_result)
                cur_test['result'] = results
                tests.append(cur_test)

        try:
            with open(filename, 'w') as json_output_file:
                # sort keys so that we have deterministic results
                json.dump(tests, json_output_file, indent=4)
        except EnvironmentError:
            logger.info("[-] Unable to open JSON file { " + filename + " } "
                        + "for writing!")
        else:
            logger.info("[+] Writing JSON file: { " + filename + " } "
                        + "successful!")


class TestResult():
    def __init__(self, result, notes=None):
        self._result = result
        self._notes = notes

    @property
    def result(self):
        return self._result

    @property
    def notes(self):
        return self._notes


class GroupTestResult():
    # GroupTestResult is a list of dicts with name and TestResult
    def __init__(self):
        self._results_list = list()

    def add_result(self, name, result):
        '''
        Add a new result to the group test results list
        :param name: Descriptive name of this test
        :param result: A TestResult indicating the result of the test
        :return: -
        '''
        new_result = dict()
        new_result['name'] = name
        new_result['result'] = result
        self._results_list.append(new_result)

    @property
    def results(self):
        '''
        Property to get the class results_list
        :return: The results list
        '''
        return self._results_list


def _build_result_string(name, result, notes, use_color, term_colors, indent):
        '''
        Internal utility function to build a result string
        :param name: Name of test
        :param result: Enum indicating the status of the test
        :param notes: Associated with the test
        :param use_color: Boolean indicating whether color should be displayed
        :param indent: Boolean indicating if test name should be indented
        :return:
        '''

        # Set the output color and text result based on test result
        result_color = ""
        pass_string = ""

        if result == Result.PASS:
            result_color = term_colors['pass']
            pass_string = 'PASS'
        elif result == Result.SKIP:
            result_color = term_colors['skip']
            pass_string = 'SKIP'
        elif result == Result.FAIL:
            result_color = term_colors['fail']
            pass_string = 'FAIL'

        tab = '     ' if indent else ''

        result_string = ""

        # Add the test name and tab if applicable
        result_string += '{0: <60}'.format(tab + name)

        # Add the color formatter if we are outputting color
        if use_color:
            result_string += result_color

        # Add the result string
        result_string += '{0: <10}'.format(pass_string)

        # If we're outputting color, terminate the color string
        if use_color:
            result_string += term_colors['end']

        # Add any notes
        if notes:
            result_string += notes

        return result_string


def _check_display_result(result, display_mode):
    '''
    Based on the display mode and the result, determine if a result should be
    shown.
    :param result: The test result
    :param display_mode: The display mode
    :return: True/False indicating whether the result should be shown
    '''
    display_result = False
    # if we're displaying everything, display
    if display_mode == ResultDisplayType.DISPLAY_ALL:
        display_result = True
    # if we're displaying anything which failed and this failed
    elif (display_mode == ResultDisplayType.DISPLAY_FAIL_ONLY and
          result == Result.FAIL):
        display_result = True
    # if we're displaying anything which isn't pass, and this is skip or fail
    elif (display_mode == ResultDisplayType.DISPLAY_NOT_PASS and
         (result == Result.FAIL or result == Result.SKIP)):
        display_result = True
    return display_result


def _get_term_colors():
    # set bash colors - try from config and fallback to constants
    term_colors = {}

    config = test_config.config

    try:
        term_colors['pass'] = config.get_config(
            "output.terminal.term_color_pass")
        term_colors['fail'] = config.get_config(
            "output.terminal.term_color_fail")
        term_colors['skip'] = config.get_config(
            "output.terminal.term_color_skip")
        term_colors['end'] = config.get_config(
            "output.terminal.term_color_end")
        for color in term_colors:
            # reconstruct proper escape sequence
            term_colors[color] = "\033[" + term_colors[color].split('[')[1]

    except ConfigNotFound:
        logger = test_utils.get_logger()
        logger.info("[*] One or more terminal colors not loaded from config, "
                    "using defaults")
        term_colors['pass'] = test_constants.term_color_pass
        term_colors['fail'] = test_constants.term_color_fail
        term_colors['skip'] = test_constants.term_color_skip
        term_colors['end'] = test_constants.term_color_end

    return term_colors


def _result_text(result):
    return_value = None
    if result == Result.PASS:
        return_value = "PASS"
    elif result == Result.FAIL:
        return_value = "FAIL"
    elif result == Result.SKIP:
        return_value = "SKIP"
    return return_value
