from reconbf.lib import test_class
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult

import glob
import os
import subprocess


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
                        for inc_path in glob.glob(statement[1]):
                            for sub_statement in _read_nginx_config(inc_path):
                                config.append(sub_statement)

                else:
                    config.append(statement)
                statement = []

        else:
            statement.append(tok)


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

    forbidden = list(set(default_protos) & bad_protos)
    if forbidden:
        res = TestResult(
            Result.FAIL,
            "nginx defaults to allowing banned protocols: %s" %
            ','.join(forbidden))
    else:
        res = TestResult(Result.PASS, "nginx defaults to secure protocols")
    results.add_result("http section", res)

    # check each server separately
    for server in _config_iter_servers(http):
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


def _expand_ssl_ciphers(ciphers):
    result = subprocess.check_output(['openssl', 'ciphers', ciphers])
    return result.decode('ascii').split(':')


def _conf_bad_ciphers():
    return ['DES', 'MD5', 'RC4', 'DSS', 'SEED', 'aNULL', 'eNULL']


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
    # create a set of ciphers we want to reject
    # let openssl expand the list of all the forbidden ones
    forbidden_ciphers = set(_expand_ssl_ciphers(':'.join(conf_ciphers)))

    if not os.path.exists(NGINX_CONFIG_PATH):
        return TestResult(Result.SKIP, "nginx config not found")

    try:
        config = _read_nginx_config('/etc/nginx/nginx.conf')
    except (ParsingError, IOError):
        return TestResult(Result.FAIL, "could not parse nginx config")

    http = _get_section(config, 'http')
    results = GroupTestResult()

    # check the default set in context 'http'
    default_ciphers = (_get_parameters(http, 'ssl_ciphers') or
                       ['HIGH:!aNULL:!MD5'])
    default_ciphers = _expand_ssl_ciphers(default_ciphers[0])

    bad_default = list(set(default_ciphers) & forbidden_ciphers)
    if bad_default:
        res = TestResult(Result.FAIL,
                         "nginx defaults to weak ciphers (%s)" %
                         ",".join(bad_default))
    else:
        res = TestResult(Result.PASS, "nginx defaults to secure ciphers")
    results.add_result("http section", res)

    # check each server separately
    for server in _config_iter_servers(http):
        name = '/'.join(_get_parameters(server, 'server_name'))
        server_ciphers = _get_parameters(server, 'ssl_ciphers')
        if server_ciphers:
            server_ciphers = _expand_ssl_ciphers(server_ciphers[0])
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
