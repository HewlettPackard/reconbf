from .logger import logger
from . import config
from . import constants

import json

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
    DISPLAY_ALL = 4           # Displays each test
    DISPLAY_NOT_PASS = 3      # Displays each test which isn't pass (fail/skip)
    DISPLAY_FAIL_ONLY = 2     # Displays each failed test and overall
    DISPLAY_OVERALL_ONLY = 1  # Displays only overall result (skip group items)


class TestResults:
    def __init__(self, results_list):
        # Results list is a list of TestResult and GroupTestResult instances
        self._results = results_list

    def add_results(self, new_results):
        """Used for adding a list of one or more TestResult or GroupTestResult
        instances to the set.

        :param new_results: A list of items to append to the list
        :returns: None
        """
        for result in new_results:
            self._results.append(result)

    def display_on_terminal(self, use_color=True,
                            display_type=ResultDisplayType.DISPLAY_NOT_PASS):
        """Pretty display of results on terminal

        :param use_color: (Optional) Boolean indicating whether to use color
        :param display_type: (Optional) ResultDisplayType indicating which
        results to display.
        :returns: -
        """

        term_colors = _get_term_colors()

        # TODO(tmcpeak): add some way of specifying a wider terminal
        widths = {'TEST_NAME': 60, 'TEST_RESULT': 10, 'TOTAL': 80}

        # used when a test name is longer than the name field, have
        # supporting details on the next line to make output nicer

        # Print header section
        print('\n')
        print('=' * widths['TOTAL'])

        print('{0: <{1}}'.format('Test Name', widths['TEST_NAME']) +
              '{0: <{1}}'.format('Result', widths['TEST_RESULT']) +
              'Notes')
        print('=' * widths['TOTAL'])

        for res in self._results:
            if isinstance(res['result'], TestResult):
                # Handle single result case

                # decide whether to display, based on mode
                if (_check_display_result(res['result'].result,
                                          display_type) or
                        display_type ==
                        ResultDisplayType.DISPLAY_OVERALL_ONLY):

                    # truncate notes to not overwhelm output
                    notes = res['result'].notes
                    if notes and len(notes) > 100:
                        notes = notes[0:97] + '...'

                    result_string = _build_result_string(res['name'],
                                                         res['result'].result,
                                                         notes,
                                                         use_color,
                                                         term_colors,
                                                         False,
                                                         widths)
                    print(result_string)

            elif isinstance(res['result'], GroupTestResult):

                child_results = []
                result_list = res['result'].results

                for child_res in result_list:

                    # check if we should display, based on the display type
                    if _check_display_result(child_res['result'].result,
                                             display_type):

                        # truncate notes to not overwhelm output
                        notes = child_res['result'].notes
                        if notes and len(notes) > 100:
                            notes = notes[0:97] + '...'

                        child_results.append(_build_result_string(
                            child_res['name'],
                            child_res['result'].result,
                            notes,
                            use_color,
                            term_colors,
                            True,
                            widths
                        ))

                parent_result = res['result'].result

                # check if we should display the parent result based on the
                # settings
                if (_check_display_result(parent_result, display_type) or
                        display_type ==
                        ResultDisplayType.DISPLAY_OVERALL_ONLY):

                    # build the parent string
                    parent_string = _build_result_string(
                        res['name'],
                        parent_result,
                        "",
                        use_color,
                        term_colors,
                        False,
                        widths)
                    print(parent_string)

                    for child_string in child_results:
                        print(child_string)

        print('\n')

    @property
    def had_failures(self):
        for result in self._results:
            if isinstance(result['result'], TestResult):
                if result['result'] == Result.FAIL:
                    return True
            elif isinstance(result['result'], GroupTestResult):
                if result['result'].result == Result.FAIL:
                    return True
        return False

    def write_csv(self, filename, separator_char=constants.CSV_SEPARATOR):
        """Create a CSV file in the specified location with an optionally
        specified separator, default: '|'

        The fields are test name, result, and notes

        Results will be output in the order errors, then failures,
        and finally successes(?)

        :param filename: The file to write
        :param separator_char: (optional) Separator character for fields
        :return: -
        """
        logger.info("Preparing to write CSV file [ {} ] ".format(filename))

        # TODO(tmcpeak): Fix write CSV to use a real CSV library
        # TODO(tmcpeak): Fix write CSV to reflect new results list structure

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
            logger.info("Unable to open CSV file [ %s ] for writing", filename)
        else:
            logger.info("Writing CSV file: [ %s ] successful ", filename)

    def write_html(self, filename, html_template,
                   display_type=ResultDisplayType.DISPLAY_NOT_PASS):
        """Creates an HTML report using a template, and outputs to the
        specified file.

        :param filename: File name to write to
        :param html_template: HTML template to use to create the report
        :return: -
        """

        RESULTS_MARKER = '$$$RESULTS$$$'

        html_rows = ""

        logger.info("Preparing to write HTML file: [ %s ]", filename)

        for res in self._results:
            if isinstance(res['result'], TestResult):
                # Handle single result case

                # decide whether to display, based on mode
                if (_check_display_result(res['result'].result,
                                          display_type) or
                        display_type ==
                        ResultDisplayType.DISPLAY_OVERALL_ONLY):

                    html_rows += _create_html_result_row(res['name'],
                                                         res['result'].result,
                                                         res['result'].notes,
                                                         False)

            elif isinstance(res['result'], GroupTestResult):
                # Handle group result case
                child_rows = []
                result_list = res['result'].results

                for child_res in result_list:

                    # check if we should display, based on the display type
                    if _check_display_result(child_res['result'].result,
                                             display_type):

                        child_rows.append(_create_html_result_row(
                            child_res['name'], child_res['result'].result,
                            child_res['result'].notes, do_indent=True))

                if res['result'].failed:
                    parent_result = Result.FAIL
                else:
                    parent_result = Result.PASS

                if (_check_display_result(parent_result, display_type) or
                        display_type ==
                        ResultDisplayType.DISPLAY_OVERALL_ONLY):

                    # build the parent string
                    parent_row = _create_html_result_row(res['name'],
                                                         parent_result,
                                                         "",
                                                         do_indent=False)

                    html_rows += parent_row

                for row in child_rows:
                    html_rows += row

        try:
            temp_file = open(html_template, 'r')
            template_content = temp_file.read()
            temp_file.close()
        except EnvironmentError:
            logger.error("Unable to open template file: [ %s ]", html_template)
            return

        template_content = template_content.replace(RESULTS_MARKER, html_rows)

        try:
            output_file = open(filename, 'w')
        except EnvironmentError:
            logger.error("Unable to open output file: [ %s ] for writing",
                         filename)
        else:
            output_file.write(template_content)
            output_file.close()
            logger.info("Successfully wrote HTML file: [ %s ]", filename)

    def write_json(self, filename):
        """Create a JSON file in the specified location

        The fields are test name, result, and notes if they exist

        :param filename:
        :returns: -
        """
        logger.info("Preparing to write JSON file [ %s ]", filename)

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
            logger.info("Unable to open JSON file [ %s ] for writing!",
                        filename)
        else:
            logger.info("Writing JSON file: [ %s ] successful!", filename)


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
        self._group_result = Result.SKIP

    def add_result(self, name, result):
        """Add a new result to the group test results list

        :param name: Descriptive name of this test
        :param result: A TestResult indicating the result of the test
        :returns: -
        """
        new_result = dict()
        new_result['name'] = name
        new_result['result'] = result

        if result.result == Result.PASS and self._group_result == Result.SKIP:
            self._group_result = Result.PASS
        elif result.result == Result.FAIL:
            self._group_result = Result.FAIL

        self._results_list.append(new_result)

    @property
    def result(self):
        """Property to return the status of the whole group

        :returns: Result
        """
        return self._group_result

    @property
    def results(self):
        """Property to get the class results_list

        :returns: The results list
        """
        return self._results_list

    def __len__(self):
        return len(self._results_list)


def _build_result_string(name, result, notes, use_color, term_colors, indent,
                         widths):
        """Internal utility function to build a result string

        :param name: Name of test
        :param result: Enum indicating the status of the test
        :param notes: Associated with the test
        :param use_color: Boolean indicating whether color should be displayed
        :param indent: Boolean indicating if test name should be indented
        :param widths: Dict with field widths
        :returns:
        """

        name_newline_str = '\n' + ' ' * widths['TEST_NAME']

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
        result_string += '{0: <{1}}'.format(tab + name, widths['TEST_NAME'])

        if len(tab + name) > widths['TEST_NAME']:
            result_string += name_newline_str

        # Add the color formatter if we are outputting color
        if use_color:
            result_string += result_color

        # Add the result string
        result_string += '{0: <{1}}'.format(pass_string, widths['TEST_RESULT'])

        # If we're outputting color, terminate the color string
        if use_color:
            result_string += term_colors['end']

        # Add any notes
        if notes:
            result_string += notes

        return result_string


def _check_display_result(result, display_mode):
    """Based on the display mode and the result, determine if a result should
    be shown.

    :param result: The test result
    :param display_mode: The display mode
    :returns: True/False indicating whether the result should be shown
    """

    # if we're displaying everything, display
    if display_mode == ResultDisplayType.DISPLAY_ALL:
        return True

    # if we're displaying anything which failed and this failed
    elif(result == Result.FAIL and display_mode >=
            ResultDisplayType.DISPLAY_FAIL_ONLY):
        return True

    # if we're displaying anything which isn't pass, and this is skip or fail
    elif(result == Result.SKIP and display_mode >=
            ResultDisplayType.DISPLAY_NOT_PASS):
        return True

    else:
        return False


def _create_html_result_row(name, result, notes, do_indent):
    """Create the HTML string for a row in the results table

    :param name: The test name
    :param result: The test result
    :param notes: Test notes
    :param do_indent: Boolean indicating whether to indent
    :return: HTML string for the row
    """

    PASS_CLASS = "test_pass"
    FAIL_CLASS = "test_fail"
    SKIP_CLASS = "test_skip"
    INDENT_CLASS = "result_indent"

    # if we're indenting, set the class style to the indent style
    indent_class = " class=" + INDENT_CLASS if do_indent else ""

    result_class = ""
    if result == Result.PASS:
        result_class = " class=" + PASS_CLASS
    elif result == Result.SKIP:
        result_class = " class=" + SKIP_CLASS
    elif result == Result.FAIL:
        result_class = " class=" + FAIL_CLASS

    row_string = ""
    row_string += "  <tr>\n"
    row_string += "    <td{}>{}</td>\n".format(indent_class, name)
    row_string += "    <td{}>{}</td>\n".format(result_class,
                                               _result_text(result))
    row_string += "    <td>{}</td>\n".format(notes)
    row_string += "  </tr>\n"

    return row_string


def _get_term_colors():
    # set bash colors - try from config and fallback to constants
    term_colors = {}

    term_colors['pass'] = config.get_config(
        "output.terminal.term_color_pass", constants.TC_PASS)
    term_colors['fail'] = config.get_config(
        "output.terminal.term_color_fail", constants.TC_FAIL)
    term_colors['skip'] = config.get_config(
        "output.terminal.term_color_skip", constants.TC_SKIP)
    term_colors['end'] = config.get_config(
        "output.terminal.term_color_end", constants.TC_END)
    for color in term_colors:
        # reconstruct proper escape sequence
        term_colors[color] = "\033[" + term_colors[color].split('[')[1]

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
