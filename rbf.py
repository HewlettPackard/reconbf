# ReconBF main module and test runner
import argparse
import os
import logging
import sys
from lib.test_class import TestSet
import lib.test_config as test_config
import lib.test_constants as test_constants
import lib.test_utils as test_utils
from lib.test_result import ResultDisplayType


def main():
    args = _parse_args()

    log_level = _log_level_from_arg(args.level)
    _init_logger(level=log_level)
    logger = test_utils.get_logger()

    _check_root()

    if not args.config_file:
        test_config.config = test_config.Config('config/rbf.cfg')
    else:
        test_config.config = test_config.Config(args.config_file)

    test_set = TestSet()
    test_set.add_from_directory(test_constants.test_dir)
    logger.info("[+] Loaded { " + str(test_set.count) + " } test cases")

    if args.script_file is not None:
        test_set.set_script(args.script_file)

    test_set.reduce_to_tags(args.tags)
    logger.info("[+] Selected { " + str(test_set.count) + " } test cases")

    results = test_set.run()
    display_mode = _get_display_type(args.display_mode)
    results.display_on_terminal(use_color=True,
                                display_type=display_mode)

    # If a report was selected, generate it
    if args.report_type is not 'none':
        _output_report(results, args.report_type, args.report_file)


def _check_root():
    '''
    Check for root, throw error and exit if not
    :return: -
    '''
    logger = test_utils.get_logger()
    if os.getuid() != 0:
        logger.error("[-] RBF must be run as root!")
        sys.exit(2)


def _get_display_type(display_mode):
    return_val = None
    if display_mode == 'all':
        return_val = ResultDisplayType.DISPLAY_ALL
    elif display_mode == 'fail':
        return_val = ResultDisplayType.DISPLAY_FAIL_ONLY
    elif display_mode == 'overall':
        return_val = ResultDisplayType.DISPLAY_OVERALL_ONLY
    elif display_mode == 'notpass':
        return_val = ResultDisplayType.DISPLAY_NOT_PASS
    return return_val


def _init_logger(level=logging.DEBUG):
    '''
    Initialize the global logger
    :return: -
    '''

    formatter = logging.Formatter(fmt=test_constants.log_format_string)

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger(test_constants.logger_name)
    logger.setLevel(level)
    logger.addHandler(handler)


def _log_level_from_arg(specified_level):
    '''
    Change user supplied log level string to logging level
    :param specified_level: User supplied string
    :return: equivalent logging level
    '''
    # default is INFO
    log_level = logging.INFO
    if specified_level == 'error':
        log_level = logging.ERROR
    elif specified_level == 'debug':
        log_level = logging.DEBUG
    return log_level


def _output_report(results, report_type, report_file):
    if report_type == 'csv':
        results.write_csv(report_file)
    elif report_type == 'json':
        results.write_json(report_file)


def _parse_args():
    '''
    Parse command line args
    :return: Selected args
    '''
    parser = argparse.ArgumentParser(
        description='ReconBF - a Python OS security feature tester')

    parser.add_argument('-c', '--config', dest='config_file', action='store',
                        default=None, type=str, help='use specified config '
                                                     'file instead of default')

    parser.add_argument('-s', '--script', dest='script_file', action='store',
                        default=None, type=str, help='run tests from a script '
                                                     'file')

    parser.add_argument('-t', '--tags', dest='tags', action='store',
                        default=[], type=str, nargs='+',
                        help='only run tests which match specified tags, ' +
                             'multiple space (" ") separated tags can be ' +
                             'listed')

    parser.add_argument('-l' '--level', dest='level', action='store',
                        choices=['debug', 'info', 'error'], default='info',
                        type=str, help='log level: can be "debug", "info", '
                                       'or "error" default=info')

    parser.add_argument('-rf', '--reportfile', dest='report_file',
                        action='store', default='result.out', type=str,
                        help='output file: default=result.out')

    parser.add_argument('-rt', '--reporttype', dest='report_type',
                        action='store', choices=['csv', 'json'],
                        default='none', type=str,
                        help='output type: can be "csv" or "json"')

    parser.add_argument('-dm', '--displaymode', dest='display_mode',
                        action='store',
                        choices=['all', 'fail', 'overall', 'notpass'],
                        default='notpass', type=str,
                        help="controls how tests are displayed: all-displays "
                             "all results, fail-displays only tests which "
                             "failed, overall-displays parent test statuses "
                             "only, notpass-displays any test which didn't "
                             "pass")

    return parser.parse_args()


if __name__ == "__main__":
    main()
