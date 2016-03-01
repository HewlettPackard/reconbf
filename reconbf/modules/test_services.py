from reconbf.lib.logger import logger
import reconbf.lib.test_class as test_class
import reconbf.lib.test_config as test_config
from reconbf.lib.test_result import GroupTestResult
from reconbf.lib.test_result import Result
from reconbf.lib.test_result import TestResult
import reconbf.lib.test_utils as test_utils


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
    results = GroupTestResult()

    try:
        config_file = config['config_file']
    except KeyError:
        logger.error("[-] Can't find definition for 'config_file' in module's "
                     "settings, skipping test")
        return TestResult(Result.SKIP, "No proper config file defined")

    service_reqs = test_config.get_reqs_from_file(config_file)

    if not service_reqs:
        return TestResult(Result.SKIP, "Unable to load module config file")
    else:
        for req in service_reqs:
            if not _check_valid_req(req):
                continue

            meets_req, reason = _does_svc_meet_run_requirement(req)

            name = req['name'] if 'name' in req else str(req['services'])
            result = Result.PASS

            if (not meets_req) and req['fail'] == 'True':
                result = Result.FAIL

            results.add_result(name, TestResult(result, reason))

    return results


@test_class.takes_config
@test_class.explanation(
    """
    Protection name: Secure service configurations

    Check: Checks that the configuration file for a service either does or
    doesn't contain specified values.

    Purpose: Many services in Linux environments can be secure or insecure,
    depending on the way that they have been configured.  A prime example is
    SSH, which can be configured securely to use strong protocols only, and not
    permit direct login to root.  Other configurations of SSH are less secure,
    and the purpose of this test is to detect insecure settings.
    """)
def test_service_config(config):
    results = GroupTestResult()

    try:
        config_file = config['config_file']
    except KeyError:
        logger.error("[-] Can't find definition for 'config_file' in module's "
                     "settings, skipping test")
        return TestResult(Result.SKIP, "No proper config file defined")

    svccfg_reqs = test_config.get_reqs_from_file(config_file)

    if not svccfg_reqs:
        return TestResult(Result.SKIP, "Unable to load module config file")

    else:

        svccfg_reqs = _validate_svc_cfg_list(svccfg_reqs)

        for req in svccfg_reqs:
            returned_results = _check_svc_config(req)

            # add all the results returned from the check function
            for name, result in returned_results:
                results.add_result(name, result)

    return results


def _check_svc_config(req):
    """Return a TestResult based on whether the specified service config
    requirement is met.  Since a service config requirement may include
    multiple settings in a single config file, this will check all
    requirements individually, and return a list of TestResults.

    :param req: Requirement specification (one entry from the config file)
    :return: A list of name, TestResult tuples to add to the group test result
    """
    return_results = []

    # the options to check are the items in the requirement other than the name
    # and config file
    checked_options = {}
    for r in req:
        if r not in ['name', 'config']:
            checked_options[r] = req[r]

    for option in checked_options:
        try:
            option_value = test_utils.config_search(req['config'], option)

        except IOError:
            # no point keep trying to check this config file if we can't open
            # it
            return_results.append((req['name'],
                                   TestResult(Result.SKIP,
                                              "Unable to open config file { " +
                                              req['config'] + " }")))
            break

        test_name = "{}: '{}'".format(req['name'], option)

        if option_value is None:
            # option_value of None means that the config option wasn't set

            # if it was supposed to be set to a value, the test fails
            if 'allowed' in checked_options[option]:

                # build note string based on the allowed value
                if checked_options[option]['allowed'] == "*":
                    allowed_val = "any value"
                else:
                    allowed_val = ("one of " +
                                   str(checked_options[option]['allowed']))

                reason = "Option expected to be " + allowed_val + ", not found"
                result = Result.FAIL

            # otherwise it passes
            else:
                reason = "Disallowed option not found"
                result = Result.PASS

        else:
            # the option value was found- if we're checking allowed then the
            # test passes when the value is in the allowed values, and fails
            # when it isn't
            if 'allowed' in checked_options[option]:
                if(checked_options[option]['allowed'] == '*' or
                        option_value in checked_options[option]['allowed']):
                    result = Result.PASS
                    reason = "Option value in expected value(s): "
                    reason += str(checked_options[option]['allowed'])

                else:
                    result = Result.FAIL
                    reason = "Option value: '{}', not in expected {}".format(
                        option_value, str(checked_options[option]['allowed']))

            # the option value was found, and we're checking if it is a
            # disallowed value, fail if it is, and pass if it isn't
            else:
                # we're checking if value is a disallowed value
                if(checked_options[option]['disallowed'] == '*' or
                        option_value in checked_options[option]['disallowed']):

                    # build note string based on the disallowed value
                    if checked_options[option]['disallowed'] == '*':
                        disallowed_val = "any value"
                    else:
                        disallowed_val = "one of " + str(
                            checked_options[option]['disallowed'])

                    result = Result.FAIL
                    reason = "Option value: '{}' ".format(option_value)
                    reason += "in disallowed value: {}".format(disallowed_val)

                else:
                    result = Result.PASS
                    reason = "Option value: {} not disallowed".format(
                        option_value)

        return_results.append((test_name, TestResult(result, reason)))

    return return_results


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

    # if the requirement does not contain all required fields
    if(not req['services'] or not req['expected'] or not req['match']
            or not req['fail']):
        logger.error("[-] Service requirement missing required field: {}".
                     format(req))
        return None

    # check correct values for requirement
    elif type(req['services']) != list:
        logger.error("[-] Expected list of services: " + req)
        return None

    elif req['expected'] not in ['on', 'off']:
        logger.error("[-] Expected value of 'on' or 'off' for 'expected': {}".
                     format(req))
        return None

    elif req['match'] not in ['all', 'one']:
        logger.error("[-] Expected value of 'all' or 'one' for 'match': {}".
                     format(req))

    elif req['fail'] not in ['True', 'False']:
        logger.error("[-] Expected value of 'True' or 'False' for 'fail': {}".
                     format(req))

    else:
        return True


def _does_svc_meet_run_requirement(req):
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

    Each service config can have "allowed" or "disallowed" each specifying
    a value of "*" or a list of values: ["a", "b"].

    If allowed and disallowed values conflict with each other, the one that
    appears second will take precedence.

    :param reqs_dict: Initial requirements dictionary from JSON config
    :returns: reqs_dict with any bad entries removed
    """

    return_list = []

    for config in reqs_list:

        # if the config check doesn't have 'name', it isn't valid, don't add
        if 'name' not in config or not isinstance(config['name'], type(u'')):
            logger.error("Service config requirement must have a 'name': {}".
                         format(config))
            continue

        # if the config check doesn't have 'config', it isn't valid, don't add
        if ('config' not in config or
                not isinstance(config['config'], type(u''))):
            logger.error("Service config requirement must have a 'config': {}".
                         format(config))
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

                    logger.error("{}: Expected a dictionary of 'allowed/"
                                 "disallowed' values, got: {}".
                                 format(config['name'],
                                        type(config[config_value])))
                    continue

                # make sure one of 'allowed' or 'disallowed' are present
                if("allowed" not in config[config_value] and
                        "disallowed" not in config[config_value]):

                    logger.error("{}: Expected 'allowed or disallowed setting "
                                 "in {}".
                                 format(config['name'],
                                        config['config_value']))
                    continue

                # ensure that each option requirement has allowed or disallowed
                # and those values are either a list of strings or '*'
                for check in config[config_value]:
                    check_value = config[config_value][check]

                    # if there are keys in the dict that aren't allowed or
                    # disallowed, then it's an improper entry
                    if check not in ["allowed", "disallowed"]:

                        logger.error("{}: Expect only 'allowed or disallowed' "
                                     "{}".
                                     format(config['name'], check_value))
                        valid_config = False

                    # if the values for the "allowed" and "disallowed" aren't
                    # a list or the string "*", then it's an improper entry
                    elif not (type(check_value) == list or
                              check_value == "*"):

                            logger.error("{} Value must be a '*' or a list of "
                                         "strings, got: {}".
                                         format(config['name'], check_value))
                            valid_config = False

        if valid_config:
            return_list.append(config)
    return return_list
