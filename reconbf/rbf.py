# ReconBF main module and test runner
from lib.logger import logger
from lib.test_class import TestSet
import lib.test_config as test_config
import lib.test_constants as test_constants
from lib.test_profile import TestProfile
from lib.test_result import ResultDisplayType

import argparse
import logging
import os
import sys


def main():
    args = _parse_args()
    profile = None

    log_level = _log_level_from_arg(args.level)
    _init_logger(level=log_level)

    _check_root()

    # if a profile was passed, set it up
    if args.profile_dir:
        profile = TestProfile(args.profile_dir)

        if not profile.is_valid():
            logger.error("[-] Problem(s) with specified profile: [ {} "
                         "]".format(args.profile_dir))
            sys.exit(2)
        else:
            logger.info("[+] Found profile: {}".format(args.profile_dir))

    # prefer: 1) profile config file   2) cmd line config file  3) default
    if profile:
        test_config.config = test_config.Config(profile.rbf_cfg)
        test_config.config.set_profile_config_path(profile.config_dir)
    elif args.config_file:
        test_config.config = test_config.Config(args.config_file)
    else:
        test_config.config = test_config.Config('config/rbf.cfg')

    test_set = TestSet()
    added = test_set.add_from_directory(test_constants.test_dir)
    logger.info("[+] Loaded [ {} ] tests".format(added))
    # if we are using a profile, load modules from it as well
    if profile:
        added = test_set.add_from_directory(profile.modules_dir)
        logger.info("[+] Loaded [ {} ] tests from profile".format(added))

    if args.script_file:
        found_script = False
        # if a profile exists, try to find the script from its scripts dir
        if profile:
            if test_set.set_script(profile.scripts_dir + '/' +
                                   args.script_file):
                logger.info("[+] Using script [ {} ] from profile".format(
                    args.script_file))
                found_script = True

        # if a script wasn't found in the profile, use one from base directory
        if not found_script:
            test_set.set_script(args.script_file)
    logger.info("[+] Selected [ {} ] tests".format(test_set.count))

    results = test_set.run()
    display_mode = _get_display_type(args.display_mode)
    results.display_on_terminal(use_color=True,
                                display_type=display_mode)

    # If a report was selected, generate it
    if args.report_type is not 'none':
        _output_report(results, args.report_type, args.report_file,
                       display_mode=display_mode, profile=profile)

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


def _output_report(results, report_type, report_file, display_mode=None,
                   profile=None):
    if report_type == 'csv':
        results.write_csv(report_file)
    elif report_type == 'json':
        results.write_json(report_file)
    elif report_type == 'html':
        config = test_config.config
        try:
            html_template = config.get_config('html_template')
        except KeyError:
            logger.error("[-] Unable to find 'html_template' setting in "
                         "config")
            sys.exit(2)
        else:
            if profile:
                templates_dir = profile.templates_dir
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

    parser.add_argument('-p', '--profile', dest='profile_dir', action='store',
                        default=None, type=str, help='use specified profile')

    parser.add_argument('-c', '--config', dest='config_file', action='store',
                        default=None, type=str, help='use specified config '
                                                     'file instead of default')

    parser.add_argument('-s', '--script', dest='script_file', action='store',
                        default=None, type=str, help='run tests from a script '
                                                     'file')

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


if __name__ == "__main__":
    # if the script is being run directly, rebase the path one dir higher
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.remove(current_dir)
    sys.path.insert(0, os.path.dirname(current_dir))
    import reconbf.rbf
    reconbf.rbf.main()
