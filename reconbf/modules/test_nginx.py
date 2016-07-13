# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from reconbf.lib import test_class
from reconbf.lib import utils
from reconbf.lib.logger import logger
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult

import glob
import os

NGINX_CONFIG_PATH = "/etc/nginx/nginx.conf"


class ParsingError(Exception):
    pass


# Without full libraries like pyparsing, we've got to simplify and do just
# enough to get the information we need.
# The rules for parsing nginx config will be as follows in pseudo-ebnf:
#  config = statement*
#  statement = token+ ";" | token "{" config "}"
#  token = non-whitespace | quoted-string
#
# Comments will be skipped during tokenization

# states:
ST_SKIP = object()  # before token
ST_TOKEN = object()  # not quoted token
ST_QUOTED = object()  # quoted string

# tokens
TOK_END_OF_STATEMENT = object()
TOK_BEGIN_BLOCK = object()
TOK_END_BLOCK = object()


def _nginx_tokenize(data):
    state = ST_SKIP

    while True:
        char = next(data)
        if state is ST_SKIP:
            if char.isspace():
                continue

            elif char == ';':
                yield TOK_END_OF_STATEMENT
                continue

            elif char == '{':
                yield TOK_BEGIN_BLOCK
                continue

            elif char == '}':
                yield TOK_END_BLOCK
                continue

            elif char == '#':
                # skip comment
                while True:
                    char = next(data)
                    if char == "\n":
                        break
                continue

            elif char == '"':
                state = ST_QUOTED
                token_buffer = ""
                continue

            else:
                token_buffer = char
                state = ST_TOKEN
                continue

        elif state is ST_TOKEN:
            if char.isspace():
                yield token_buffer
                state = ST_SKIP
                continue

            elif char == ';':
                yield token_buffer
                yield TOK_END_OF_STATEMENT
                state = ST_SKIP
                continue

            elif char == '{':
                yield token_buffer
                yield TOK_BEGIN_BLOCK
                state = ST_SKIP
                continue

            elif char == '#':
                # skip comment
                while True:
                    char = next(data)
                    if char == "\n":
                        break
                state = ST_SKIP
                continue

            else:
                token_buffer += char
                continue

        elif state is ST_QUOTED:
            if char == '\\':
                char = next(data)
                if char == 'n':
                    token_buffer += '\n'
                else:
                    token_buffer += char
                continue

            elif char == '"':
                yield token_buffer
                state = ST_SKIP
                continue

            else:
                token_buffer += char
                continue


def _nginx_parse(tokens):
    config = []
    statement = []

    while True:
        try:
            tok = next(tokens)
        except StopIteration:
            return config

        if tok is TOK_BEGIN_BLOCK:
            statement.append(_nginx_parse(tokens))
            config.append(statement)
            statement = []

        elif tok is TOK_END_BLOCK:
            if statement:
                config.append(statement)
                statement = []
            return config

        elif tok is TOK_END_OF_STATEMENT:
            if statement:
                # special-case config includes
                if statement[0] == 'include':
                    if len(statement) != 2:
                        raise ParsingError("include option must be followed "
                                           "by one path, got %s" % statement)
                    else:
                        if os.path.isabs(statement[1]):
                            glob_str = statement[1]
                        else:
                            glob_str = os.path.join(
                                os.path.dirname(NGINX_CONFIG_PATH),
                                statement[1])
                        inc_paths = glob.glob(glob_str)
                        if not inc_paths:
                            logger.warning("include name '%s' did not resolve "
                                           "to any existing files",
                                           statement[1])
                        for inc_path in inc_paths:
                            for sub_statement in _read_nginx_config(inc_path):
                                config.append(sub_statement)

                else:
                    config.append(statement)
                statement = []

        else:
            statement.append(tok)


@utils.idempotent
def _read_nginx_config(path):
    with open(path, 'r') as f:
        config = f.read()
    token_stream = _nginx_tokenize(iter(config))
    return _nginx_parse(token_stream)


def _config_iter_servers(http):
    """Iterate all server blocks in provided config section."""
    for statement in http:
        if statement[0] == 'server':
            yield statement[1]


def _get_parameters(conf, option):
    """Get a statement where the first token is the same as option."""
    for statement in conf:
        if statement[0] == option:
            return statement[1:]
    return None


def _get_section(conf, section):
    for statement in conf:
        if statement[0] == section:
            if not isinstance(statement[1], list):
                raise ParsingError("expected section contents")
            return statement[1]
    return None


def _server_enables_ssl(conf):
    for statement in conf:
        if statement[0] == 'listen':
            if 'ssl' in statement[1:]:
                return True
        elif statement[0] == 'ssl' and statement[1] == 'on':
            return True
    return False


def _conf_bad_protos():
    return ['SSLv2', 'SSLv3']


@test_class.takes_config(_conf_bad_protos)
@test_class.explanation("""
    Protection name: Forbid known broken protocols

    Check: Make sure that neither the default configuration nor
    any of the server sections allows a SSL/TLS version which is
    known to be broken.

    Purpose: Currently SSL versions 1/2/3 are known to have issues
    which cannot be easily secured. This check will make sure that
    none of the configured servers use them. Alternatively, more
    banned protocols can be added in configuration.
    """)
def ssl_protos(bad_protos):
    bad_protos = set(bad_protos)
    results = GroupTestResult()
    config = _read_nginx_config('/etc/nginx/nginx.conf')
    http = _get_section(config, 'http')

    # check the default set in context 'http'
    default_protos = (_get_parameters(http, 'ssl_protocols') or
                      ['TLSv1', 'TLSv1.1', 'TLSv1.2'])

    # check each server separately
    for server in _config_iter_servers(http):
        if not _server_enables_ssl(server):
            continue

        name = '/'.join(_get_parameters(server, 'server_name'))
        server_protos = (_get_parameters(server, 'ssl_protocols') or
                         default_protos)
        forbidden = list(set(server_protos) & bad_protos)
        if forbidden:
            res = TestResult(Result.FAIL,
                             "server uses banned protocols: %s" %
                             ",".join(forbidden))
        else:
            res = TestResult(Result.PASS, "")
        results.add_result("server %s" % name, res)

    return results


def _conf_bad_ciphers():
    return ['DES', 'MD5', 'RC4', 'SEED', 'aNULL', 'eNULL']


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
def ssl_ciphers(conf_ciphers):
    if not os.path.exists(NGINX_CONFIG_PATH):
        return TestResult(Result.SKIP, "nginx config not found")

    # create a set of ciphers we want to reject
    # let openssl expand the list of all the forbidden ones
    try:
        forbidden_ciphers = set(
            utils.expand_openssl_ciphers(':'.join(conf_ciphers)))
    except Exception:
        return TestResult(Result.SKIP,
                          "Cannot use openssl to expand cipher list")

    try:
        config = _read_nginx_config('/etc/nginx/nginx.conf')
    except (ParsingError, IOError):
        return TestResult(Result.FAIL, "could not parse nginx config")

    http = _get_section(config, 'http')
    results = GroupTestResult()

    # check the default set in context 'http'
    default_ciphers = (_get_parameters(http, 'ssl_ciphers') or
                       ['HIGH:!aNULL:!MD5'])
    default_ciphers = utils.expand_openssl_ciphers(default_ciphers[0])

    # check each server separately
    for server in _config_iter_servers(http):
        if not _server_enables_ssl(server):
            continue

        name = '/'.join(_get_parameters(server, 'server_name'))
        server_ciphers = _get_parameters(server, 'ssl_ciphers')
        if server_ciphers:
            server_ciphers = utils.expand_openssl_ciphers(server_ciphers[0])
        else:
            server_ciphers = default_ciphers

        bad_ciphers = list(set(server_ciphers) & forbidden_ciphers)
        if bad_ciphers:
            res = TestResult(Result.FAIL,
                             "uses weak ciphers (%s)" %
                             ",".join(bad_ciphers))
        else:
            res = TestResult(Result.PASS, "")
        results.add_result("server %s" % name, res)

    return results


@test_class.explanation("""
    Protection name: Check certificates sanity.

    Check: Validate a number of properties of the provided SSL
    certificates. This includes the stock openssl verification
    as well as custom.

    Purpose: Certificates can be a weak point of an SSL
    connection. This check validates some simple
    properties of
    the provided certificate. This includes:
    - 'openssl verify' validation
    - signature algorithm blacklist
    - key size check
    """)
def ssl_cert():
    if not os.path.exists(NGINX_CONFIG_PATH):
        return TestResult(Result.SKIP, "nginx config not found")

    try:
        config = _read_nginx_config('/etc/nginx/nginx.conf')
    except (ParsingError, IOError):
        return TestResult(Result.FAIL, "could not parse nginx config")

    http = _get_section(config, 'http')
    results = GroupTestResult()

    default_certificate = _get_parameters(http, 'ssl_certificate')
    if default_certificate:
        default_issues = utils.find_certificate_issues(default_certificate)

    for server in _config_iter_servers(http):
        if not _server_enables_ssl(server):
            continue

        name = '/'.join(_get_parameters(server, 'server_name'))
        certificate = _get_parameters(server, 'ssl_certificate')

        if certificate:
            issues = utils.find_certificate_issues(certificate[0])
        elif default_certificate:
            issues = default_issues

        if certificate or default_certificate:
            if issues:
                res = TestResult(
                    Result.FAIL,
                    "certificate %s invalid: %s" % (certificate[0], issues))
            else:
                res = TestResult(Result.PASS, "ssl certificate ok")
        else:
            res = TestResult(Result.FAIL, "ssl certificate not configured")
        results.add_result("server %s" % name, res)

    return results


@test_class.explanation("""
    Protection name: Don't advertise version.

    Check: Verify that none of the servers advertises the
    nginx version in the result.

    Purpose: While hiding the version does not make nginx
    any more secure, it can result in less exposure.
    Specifically, if the server version is not immediately
    available from indexes like shodan.io, it's less likely
    to be directly targetted when specific versions are
    vulnerable.
    To stop advertising version, set "server_tokens off".
    """)
def version_advertise():
    if not os.path.exists(NGINX_CONFIG_PATH):
        return TestResult(Result.SKIP, "nginx config not found")

    try:
        config = _read_nginx_config('/etc/nginx/nginx.conf')
    except (ParsingError, IOError):
        return TestResult(Result.FAIL, "could not parse nginx config")

    http = _get_section(config, 'http')
    results = GroupTestResult()

    default_tokens = _get_parameters(http, 'server_tokens') or 'on'

    for server in _config_iter_servers(http):
        name = '/'.join(_get_parameters(server, 'server_name'))
        tokens = _get_parameters(server, 'server_tokens')

        if (tokens or default_tokens) == 'on':
            res = TestResult(Result.FAIL,
                             "version is advertised (server_tokens)")
        else:
            res = TestResult(Result.PASS, "custom or hidden version")
        results.add_result("server %s" % name, res)

    return results
