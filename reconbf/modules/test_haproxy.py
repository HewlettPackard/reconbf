from reconbf.lib import test_class
from reconbf.lib import utils
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult

import collections
import logging


logger = logging.getLogger(__name__)


HAPROXY_CONFIG_PATH = '/etc/haproxy/haproxy.cfg'
REPEATING_OPTIONS = ['bind', 'option', 'errorfile']


class ParsingError(Exception):
    pass


def _read_config(path):
    with open(path, 'r') as f:
        conf_lines = f.readlines()

    config = collections.defaultdict(dict)
    section = None

    for lineno, line in enumerate(conf_lines):
        # strip comment
        try:
            comment_start = line.index('#')
        except ValueError:
            pass  # no comment found
        else:
            line = line[:comment_start]

        line = line.strip()
        if not line:
            continue

        parts = [p.strip() for p in line.split(' ')]
        if parts[0] in ('global', 'defaults'):
            section = parts[0]
            continue
        elif parts[0] in ('listen', 'frontend', 'backend'):
            if len(line) == 1:
                logger.warning("section '%s' is missing a name, ignoring line",
                               parts[0])
                continue
            else:
                section = '/'.join(parts)
            continue

        if section is None:
            logger.warning("option outside of any section, ignoring")
            continue

        key = parts[0]
        if len(parts) == 1:
            val = None
        else:
            val = parts[1:]

        if key in REPEATING_OPTIONS:
            if key not in config[section]:
                config[section][key] = []
            config[section][key].append(val)
        else:
            config[section][key] = val

    return config


def _conf_bad_ciphers():
    return {
        'configs': '/etc/haproxy/haproxy.cfg',
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
    try:
        config = _read_config(test_config['configs'])
    except IOError:
        return TestResult(Result.SKIP, "haproxy config not found")

    bad_ciphers_desc = ':'.join(test_config['bad_ciphers'])
    try:
        bad_ciphers = set(utils.expand_openssl_ciphers(bad_ciphers_desc))
    except Exception:
        return TestResult(Result.SKIP,
                          "Cannot use openssl to expand cipher list")
    results = GroupTestResult()

    # no need to check the options if haproxy doesn't handle ssl traffic
    frontends_with_ssl = set()
    backends_with_ssl = set()
    for section in config:
        if section.startswith('frontend') or section.startswith('listen'):
            for bind in config[section].get('bind', []):
                if 'ssl' in bind:
                    frontends_with_ssl.add(section)
        if section.startswith('backend') or section.startswith('listen'):
            for server in config[section].get('server', []):
                if 'check-ssl' in server:
                    backends_with_ssl.add(section)
                if 'ssl' in server:
                    backends_with_ssl.add(section)

    if not frontends_with_ssl and not backends_with_ssl:
        return TestResult(Result.SKIP, "no section enables ssl")

    # there are two defaults - for incoming and outgoing connections
    default_bind_ciphers_desc = config['global'].get(
        'ssl-default-bind-ciphers', ['DEFAULT'])[0]
    default_bind_ciphers = utils.expand_openssl_ciphers(
        default_bind_ciphers_desc)
    default_server_ciphers_desc = config['global'].get(
        'ssl-default-server-ciphers', ['DEFAULT'])[0]
    default_server_ciphers = utils.expand_openssl_ciphers(
        default_server_ciphers_desc)

    if frontends_with_ssl:
        failures = ','.join(set(default_bind_ciphers) & bad_ciphers)
        test_name = "default-bind-ciphers"
        if failures:
            msg = "forbidden ciphers: %s" % failures
            results.add_result(test_name, TestResult(Result.FAIL, msg))
        else:
            results.add_result(test_name, TestResult(Result.PASS))

    if backends_with_ssl:
        failures = ','.join(set(default_server_ciphers) & bad_ciphers)
        test_name = "default-server-ciphers"
        if failures:
            msg = "forbidden ciphers: %s" % failures
            results.add_result(test_name, TestResult(Result.FAIL, msg))
        else:
            results.add_result(test_name, TestResult(Result.PASS))

    for section in config:
        # don't check anything that doesn't enable ssl
        if section not in (backends_with_ssl | frontends_with_ssl):
            continue

        section_ciphers_desc = config[section].get('ciphers', [None])[0]
        if section_ciphers_desc:
            section_ciphers = utils.expand_openssl_ciphers(
                section_ciphers_desc)
        else:
            if section.startswith('backend'):
                section_ciphers = default_server_ciphers
            elif section.startswith('frontend'):
                section_ciphers = default_bind_ciphers
            elif section.startswith('listen'):
                section_ciphers = default_bind_ciphers

        failures = ','.join(set(section_ciphers) & bad_ciphers)
        if failures:
            msg = "forbidden ciphers: %s" % failures
            results.add_result(section, TestResult(Result.FAIL, msg))
        else:
            results.add_result(section, TestResult(Result.PASS))

    return results
