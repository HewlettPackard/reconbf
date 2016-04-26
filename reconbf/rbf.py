# ReconBF main module and test runner
from .lib.logger import logger
from .lib.test_class import TestSet
from .lib import config
from .lib import test_constants as test_constants
from .lib.result import ResultDisplayType

import argparse
import logging
import os
import sys


def main():
    args = _parse_args()

    log_level = _log_level_from_arg(args.level)
    _init_logger(level=log_level)

    _check_root()

    # prefer: 1) cmd line config file  2) default
    if args.config_file:
        config.config = config.Config(args.config_file)
    else:
        config.config = config.Config('config/rbf.cfg')

    test_set = TestSet()
    added = test_set.add_known_tests(
        config.get_configured_modules())
    logger.info("[+] Loaded [ {} ] tests".format(added))

    results = test_set.run()
    display_mode = _get_display_type(args.display_mode)
    results.display_on_terminal(use_color=True,
                                display_type=display_mode)

    # If a report was selected, generate it
    if args.report_type is not 'none':
        _output_report(results, args.report_type, args.report_file,
                       display_mode=display_mode)

    if results.had_failures:
        sys.exit(1)
    else:
        sys.exit(0)


def _check_root():
    """Check for root, throw error and exit if not

    :return: -
    """
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


def _log_level_from_arg(specified_level):
    """Change user supplied log level string to logging level

    :param specified_level: User supplied string
    :return: equivalent logging level
    """
    # default is INFO
    log_level = logging.INFO
    if specified_level == 'error':
        log_level = logging.ERROR
    elif specified_level == 'debug':
        log_level = logging.DEBUG
    return log_level


def _init_logger(level):
    formatter = logging.Formatter(fmt=test_constants.log_format_string)

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    global_logger = logging.getLogger(test_constants.logger_name)
    global_logger.setLevel(level)
    global_logger.addHandler(handler)


def _output_report(results, report_type, report_file, display_mode=None):
    if report_type == 'csv':
        results.write_csv(report_file)
    elif report_type == 'json':
        results.write_json(report_file)
    elif report_type == 'html':
        try:
            html_template = config.get_config('html_template')
        except KeyError:
            logger.error("[-] Unable to find 'html_template' setting in "
                         "config")
            sys.exit(2)
        else:
            templates_dir = 'templates'

            html_template = templates_dir + '/' + html_template
            logger.info("[+] Using template from {}".format(html_template))
            results.write_html(report_file, html_template, display_mode)


def _parse_args():
    """Parse command line args

    :return: Selected args
    """
    parser = argparse.ArgumentParser(
        description='ReconBF - a Python OS security feature tester')

    parser.add_argument('-c', '--config', dest='config_file', action='store',
                        default=None, type=str, help='use specified config '
                                                     'file instead of default')

    parser.add_argument('-l' '--level', dest='level', action='store',
                        choices=['debug', 'info', 'error'], default='info',
                        type=str, help='log level: can be "debug", "info", '
                                       'or "error" default=info')

    parser.add_argument('-rf', '--reportfile', dest='report_file',
                        action='store', default='result.out', type=str,
                        help='output file: default=result.out')

    parser.add_argument('-rt', '--reporttype', dest='report_type',
                        action='store', choices=['csv', 'json', 'html'],
                        default='none', type=str,
                        help='output type: can be "csv", "json", or "html"')

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
