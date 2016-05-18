from reconbf.lib import test_class
from reconbf.lib import utils
from reconbf.lib.logger import logger
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult

import collections
import glob
import os


def _read_config(path, config=collections.defaultdict(dict), section=None):
    with open(path, 'r') as f:
        conf_lines = f.readlines()

    for lineno, line in enumerate(conf_lines):
        # strip comment
        try:
            comment_start = line.rindex(';')
        except ValueError:
            pass  # no comment found
        else:
            line = line[:comment_start]

        line = line.strip()
        if not line:
            continue

        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            continue

        parts = line.split('=', 1)
        if len(parts) != 2:
            logger.warning("Could not parse line %i in config '%s'",
                           lineno + 1, path)
            continue

        key = parts[0].strip()
        val = parts[1].strip()

        if key == 'include':
            for d_path in os.listdir(val):
                conf_path = os.path.join(d_path, path)
                _read_config(conf_path, config, section)

        if key == 'options':
            # special case, there can be multiple values
            if key in config[section]:
                config[section][key].append(val)
            else:
                config[section][key] = [val]
        else:
            config[section][key] = val

    return config


def _merge_options(current, new):
    for option in new:
        if option.startswith('-'):
            try:
                current.remove(option[1:])
            except ValueError:
                pass
        else:
            current.append(option)


def _find_bad_options(options, test_config):
    bad = []
    for opt in test_config.get('enforce', []):
        if opt not in options:
            bad.append(opt + ' missing')
    for opt in test_config.get('forbid', []):
        if opt in options:
            bad.append(opt + 'forbidden')
    return bad


def _conf_ssl_options():
    return {
        'configs': '/etc/stunnel/*.conf',
        'enforce': ['NO_SSLv2', 'NO_SSLv3', 'NO_COMPRESSION'],
        'forbid': [],
    }


@test_class.takes_config(_conf_ssl_options)
@test_class.explanation("""
    Protection name: Forbid bad SSL options

    Check: Make sure that neither the default configuration nor
    any of the server sections allows forbidden options.

    Purpose: Enforces or forbids specific openssl options. These may
    prevent/mitigate known vulnerabilities. By default the following
    options are enforced:
    - NO_SSLv2 (because of DROWN and others)
    - NO_SSLv3 (because of POODLE and others)
    - NO_COMPRESSION (because of CRIME)
    """)
def ssl_options(test_config):
    results = GroupTestResult()

    paths = glob.glob(test_config['configs'])
    if not paths:
        return TestResult(Result.SKIP, "No stunnel config found")

    for path in paths:
        config = _read_config(path)
        default_options = ['NO_SSLv2', 'NO_SSLv3']
        options = config[None].get('options', [])
        _merge_options(default_options, options)

        bad_options = _find_bad_options(default_options, test_config)
        if not bad_options:
            results.add_result('%s:default' % path, TestResult(Result.PASS))
        else:
            for explanation in bad_options:
                results.add_result('%s:default' % path,
                                   TestResult(Result.FAIL, explanation))

        for section in config:
            if section is None:
                continue
            section_options = default_options[:]
            options = config[section].get('options', [])
            _merge_options(section_options, options)

            bad_options = _find_bad_options(section_options, test_config)
            if not bad_options:
                results.add_result('%s:%s' % (path, section),
                                   TestResult(Result.PASS))
            else:
                for explanation in bad_options:
                    results.add_result('%s:%s' % (path, section),
                                       TestResult(Result.FAIL, explanation))
    return results


def _conf_bad_ciphers():
    return {
        'configs': '/etc/stunnel/*.conf',
        'bad_ciphers': ['DES', 'MD5', 'RC4', 'DSS', 'SEED', 'aNULL', 'eNULL'],
        }


@test_class.takes_config(_conf_bad_ciphers)
@test_class.explanation("""
    Protection name: Forbid known broken and weak protocols

    Check: Make sure that neither the default configuration nor
    any of the server sections allows ciphers which are known
    to be weak or broken.

    Purpose: OpenSSL comes with ciphers which should not be used
    in production. For example MD5 and RC4 algorithms have known
    issues when applied in SSL/TLS context. This check will list
    all available OpenSSL ciphers and make sure that the configured
    ciphers are not allowed.

    For information about a secure string, see
    https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/
    """)
def ssl_ciphers(test_config):
    paths = glob.glob(test_config['configs'])
    if not paths:
        return TestResult(Result.SKIP, "No stunnel config found")

    bad_ciphers_desc = ':'.join(test_config['bad_ciphers'])
    try:
        bad_ciphers = set(utils.expand_openssl_ciphers(bad_ciphers_desc))
    except Exception:
        return TestResult(Result.SKIP,
                          "Cannot use openssl to expand cipher list")
    results = GroupTestResult()

    for path in paths:
        config = _read_config(path)
        default_ciphers_desc = config[None].get('ciphers', 'DEFAULT')
        default_ciphers = utils.expand_openssl_ciphers(default_ciphers_desc)
        failures = ','.join(set(default_ciphers) & bad_ciphers)
        test_name = "%s:default" % path
        if failures:
            msg = "forbidden ciphers: %s" % failures
            results.add_result(test_name, TestResult(Result.FAIL, msg))
        else:
            results.add_result(test_name, TestResult(Result.PASS))

        for section in config:
            section_ciphers_desc = config[section].get('ciphers')
            if section_ciphers_desc:
                section_ciphers = utils.expand_openssl_ciphers(
                    section_ciphers_desc)
            else:
                section_ciphers = default_ciphers
            failures = ','.join(set(section_ciphers) & bad_ciphers)
            test_name = "%s:%s" % (path, section)
            if failures:
                msg = "forbidden ciphers: %s" % failures
                results.add_result(test_name, TestResult(Result.FAIL, msg))
            else:
                results.add_result(test_name, TestResult(Result.PASS))

    return results


def _conf_certificate_check():
    return {
        'configs': '/etc/stunnel/*.conf',
        }


@test_class.takes_config(_conf_certificate_check)
@test_class.explanation("""
    Protection name: Check certificates sanity.

    Check: Validate a number of properties of the provided SSL
    certificates. This includes the stock openssl verification
    as well as custom.

    Purpose: Certificates can be a weak point of an SSL
    connection. This check validates some simple properties of
    the provided certificate. This includes:
    - 'openssl verify' validation
    - signature algorithm blacklist
    - key size check
    """)
def certificate_check(test_config):
    paths = glob.glob(test_config['configs'])
    if not paths:
        return TestResult(Result.SKIP, "No stunnel config found")

    results = GroupTestResult()

    for path in paths:
        config = _read_config(path)

        for section in config:
            cert_path = config[section].get('cert')
            # do this check only on sections with configured certificates
            if not cert_path:
                continue

            issues = utils.find_certificate_issues(cert_path)
            test_name = "%s:%s" % (path, section)
            if issues:
                msg = "problem in %s: %s" % (cert_path, issues)
                results.add_result(test_name, TestResult(Result.FAIL, msg))
            else:
                results.add_result(test_name, TestResult(Result.PASS))

    return results
