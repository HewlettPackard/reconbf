import lib.test_class as test_class
from lib.test_result import GroupTestResult
from lib.test_result import Result
from lib.test_result import TestResult
import lib.test_utils as test_utils


@test_class.takes_config
@test_class.explanation(
    """
    Protection name: Running services

    Check: This checks that groups of services are either running or not
    running.  Which services are checked and how they are checked are
    configurable.

    Purpose: The services that are running make a big difference in the
    security of a system.  Some services add security to a system, such as a
    firewall service, which is used to block unsolicited network connections.
    Some services great detract from the security of a system, such as a
    running telnet server, which can allow users to log in by passing their
    credentials unencrypted.  This provides attackers with a path to gain
    access to the system.
    """)
def test_running_services(config):
    logger = test_utils.get_logger()

    try:
        config_file = config['config_file']
        service_reqs = test_utils.get_reqs_from_file(config_file)

    # things that are going to make us skip the test:
    #  1) Can't find entry for 'config_file' which points to the json file
    #     that actually lists the files and permissions to check
    #  2) Can't find/open that json file
    #  3) File isn't valid json
    except KeyError:

        logger.error("[-] Can't find definition for 'config_file' in module's "
                     "settings, skipping test")

    # if we got exceptions when trying to read the config, skip the test
    except EnvironmentError:
        pass
    except ValueError:
        pass

    else:
        results = GroupTestResult()

        for req in service_reqs:
            if not _check_valid_req(req):
                continue

            meets_req, reason = _does_meet_requirement(req)

            name = req['name'] if 'name' in req else str(req['services'])
            result = Result.PASS

            if (not meets_req) and req['fail'] == 'True':
                result = Result.FAIL

            results.add_result(name, TestResult(result, reason))

        return results

    return TestResult(Result.SKIP, "Invalid test configuration")


@test_class.takes_config
@test_class.explanation(
    """
    Protection name:

    Check:

    Purpose:
    """)
def test_service_config(config):
    logger = test_utils.get_logger()

    try:
        config_file = config['config_file']
        svccfg_reqs = test_utils.get_reqs_from_file(config_file)

    # things that are going to make us skip the test:
    #  1) Can't find entry for 'config_file' which points to the json file
    #     that actually lists the files and permissions to check
    #  2) Can't find/open that json file
    #  3) File isn't valid json
    except KeyError:

        logger.error("[-] Can't find definition for 'config_file' in module's "
                     "settings, skipping test")

    # if we got exceptions when trying to read the config, skip the test
    except EnvironmentError:
        pass
    except ValueError:
        pass

    else:
        svccfg_reqs = _validate_svc_cfg_list(svccfg_reqs)


def _check_valid_req(req):
    """Utility function to check if a requirement entry in the config file is
    valid.  A valid entry has

    services - A list of strings, each representing a service name
    expected - Either 'on' or 'off' representing whether the service is
        expected to be running or not
    match - Either 'all' or 'one' indicating whether all services must match
        expected or just one
    fail - 'True' or 'False' indicating whether failure to meet this check
        should cause the test to fail or just note the results

    :param req: Requirement dictionary parsed from JSON in the config file
    :returns: None if the requirement is not valid, otherwise True
    """

    logger = test_utils.get_logger()

    # if the requirement does not contain all required fields
    if(not req['services'] or not req['expected'] or not req['match']
            or not req['fail']):
        logger.error("[-] Service requirement missing required field: " + req)
        return None

    # check correct values for requirement
    elif type(req['services']) != list:
        logger.error("[-] Expected list of services: " + req)
        return None

    elif req['expected'] not in ['on', 'off']:
        logger.error("[-] Expected value of 'on' or 'off' for 'expected': " +
                     req)
        return None

    elif req['match'] not in ['all', 'one']:
        logger.error("[-] Expected value of 'all' or 'one' for 'match': " +
                     req)

    elif req['fail'] not in ['True', 'False']:
        logger.error("[-] Expected value of 'True' or 'False' for 'fail': " +
                     req)

    else:
        return True


def _does_meet_requirement(req):
    """Utility function to check if a service requirement is met

    :param req: dictionary representing an entry in the services config file
    :returns: True/False indicating whether the service requirement was met
    """
    reasons = []

    expected = False
    if req['expected'] == 'on':
        expected = True

    # if we require all to match, we'll fail the check if one isn't as expected
    if req['match'] == 'all':
        passed = True
        for service in req['services']:
            if test_utils.is_service_running(service) != expected:
                passed = False
                reasons.append("{} not {}".format(service, req['expected']))

    # otherwise, we just need one to match, as soon as a match is found, pass
    else:
        passed = False
        for service in req['services']:
            if test_utils.is_service_running(service) == expected:
                passed = True
        if not passed:
            reasons.append("None of {} are {}".format(str(req['services']),
                                                      req['expected']))

    reason = ', '.join(map(str, reasons))

    return passed, reason


def _validate_svc_cfg_list(reqs_list):
    """Ensures that the service config passed in configuration is valid,
    displays logger errors in case of any malformed entries.

    Each service config entry is expected to have a "name", "config", and one
    or more service config requirements.

    For each service config requirement, the setting in the file is specified
    as follows

    [section_name]
    setting value

    The service config for this would be:

    "section_name.setting" : { "allowed": ["value"] }

    Each service config can have "allowed" and/or "disallowed" each specifying
    a value of "*" or a list of values: ["a", "b"].

    If allowed and disallowed values conflict with each other, the one that
    appears second will take precedence.

    :param reqs_dict: Initial requirements dictionary from JSON config
    :return: reqs_dict with any bad entries removed
    """

    return_list = []

    for config in reqs_list:
        # if the config check doesn't have 'name', it isn't valid, don't add
        if 'name' not in config or not type(config['name']) == unicode:
            test_utils.get_logger().error("Service config requirement must " +
                                          "have a 'name': " + str(config))
            continue

        # if the config check doesn't have 'config', it isn't valid, don't add
        if 'config' not in config or not type(config['config']) == unicode:
            test_utils.get_logger().error("Service config requirement must " +
                                          "have a 'config': " + str(config))
            continue

        # have we seen something in this config that makes it invalid?
        valid_config = True

        for config_value in config:
            if config_value == 'name' or config_value == 'config':
                pass
            # go through everything in the requirement that isn't name or
            # config, we're expecting to see a dictionary with the keys
            # allowed or disallowed only, each of which should have either
            # the string value "*" or a list of strings

            else:
                # make sure that the config contains a dict
                if type(config[config_value]) != dict:
                    log_msg = 'Expected a dictionary of "allowed"/"disallowed"'
                    log_msg += ' values, got: '
                    log_msg += str(type(config[config_value]))
                    test_utils.get_logger().error(log_msg)
                    continue

                for check in config[config_value]:
                    check_value = config[config_value][check]

                    # if there are keys in the dict that aren't allowed or
                    # disallowed, then it's an improper entry
                    if check not in ["allowed", "disallowed"]:
                        log_msg = 'Expect only "allowed" or "disallowed": '
                        log_msg += str(check_value)
                        test_utils.get_logger().error(log_msg)
                        valid_config = False

                    # if the values for the "allowed" and "disallowed" aren't
                    # a list or the string "*", then it's an improper entry
                    else:
                        if not (type(check_value) == list or
                                check_value == "*"):

                            log_msg = 'Value must be a "*" or a list of '
                            log_msg += "strings, got: " + str(check_value)
                            test_utils.get_logger().error(log_msg)
                            valid_config = False

        if valid_config:
            return_list.append(config)
    return return_list