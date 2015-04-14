from lib.test_class import TestSet
import lib.test_constants as test_constants

import argparse
import sys


def main():
    args = _parse_args()

    test_set = TestSet()
    test_set.add_from_directory(test_constants.test_dir)

    if args.list:
        _display_test_list(test_set)
    if args.explain_test:
        _display_test_explain(test_set, args.explain_test)

    if not args.list and not args.explain_test:
        print("No arguments specified... run 'tests.py -h' for help")
        sys.exit(2)


def _parse_args():
    """Parse command line args

    :returns: Selected args
    """
    parser = argparse.ArgumentParser(
        description='Test list/describe utility for ReconBF')

    parser.add_argument('-l', '--list', action='store_true',
                        help='list all of the tests sorted by module/test ' +
                             'name')
    parser.add_argument('-e', '--explain', dest='explain_test', action='store',
                        type=str, help='show full explanation for a test.  '
                        'Example: -e test_file_perms.test_file_perms or '
                        '-e test_app_armor')

    return parser.parse_args()


def _display_test_list(test_set):
    tests_list = []
    for test in test_set.tests:
        cur_test = _build_test_dict(test)
        tests_list.append(cur_test)

    # sort by module name and test name
    sorted_list = sorted(tests_list, key=lambda k:
                         str(k['module'] + "." + k['test']))

    for item in sorted_list:
        _print_test(item, explanation_type=PrintExplanationType.ONE_LINE)


def _display_test_explain(test_set, test_id):
    fully_qual = False
    module = ''

    has_displayed = False

    if '.' in test_id:
        fully_qual = True
        module = test_id.split('.')[0]
        name = test_id.split('.')[1]
    else:
        name = test_id

    for test in test_set.tests:
        if name == test['name']:
            # we have a match
            if not fully_qual or (fully_qual and module == test['module']):
                cur_test = _build_test_dict(test)
                has_displayed = True
                _print_test(cur_test,
                            explanation_type=PrintExplanationType.FULL)

    if not has_displayed:
        print_str = "No match found for specified test: {" + test_id + "}. "
        print_str += "Please check spelling and try again."
        print(print_str)


def _build_test_dict(test_item):
    ret_value = dict()
    ret_value['module'] = test_item['module']
    ret_value['test'] = test_item['name']

    if hasattr(test_item['function'], 'explanation'):
        ret_value['explanation'] = test_item['function'].explanation
    else:
        ret_value['explanation'] = ""

    return ret_value


class PrintExplanationType:
    def __init__(self):
        pass

    NONE = 1
    ONE_LINE = 2
    FULL = 3


def _print_test(test_dict, explanation_type=PrintExplanationType.ONE_LINE,
                do_indent=False):
    if do_indent:
        indent = "     "
    else:
        indent = ""

    max_line_length = test_constants.max_line_length

    print_string = ""
    print_string += '{0: <50}'.format(indent + test_dict['module'] +
                                      '.' + test_dict['test'])

    if explanation_type == PrintExplanationType.ONE_LINE:
        explain_length = max_line_length - 70

        explanation_lines = test_dict['explanation'].split('\n')
        # we'll use the first line which contains non-whitespace chars
        first_line = None
        for line in explanation_lines:
            if (len(line.replace(' ', '').replace('\n', '')) > 0 and
                    not first_line):
                first_line = line
        if first_line:
            print_string += ('{0: <%d}' % explain_length).format(
                first_line[:explain_length])

    elif explanation_type == PrintExplanationType.FULL:
        print_string += test_dict['explanation']

    else:
        pass

    print(print_string)

if __name__ == "__main__":
    main()
