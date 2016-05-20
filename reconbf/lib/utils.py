from .logger import logger
from . import config
from . import constants
from .result import Result, TestResult

from collections import defaultdict
import glob
import gzip
import os
import re
import subprocess
import functools

"""
This module is where utility functions which are generally useful to tests
should be defined.
"""


class ValNotFound(Exception):
    pass


def check_path_exists(path):
    """Checks for the existence of a path

    :param path: The path to check
    :returns: True or False
    """
    logger.debug("Testing for existence of path { %s }", path)

    return_value = os.path.exists(path)
    if return_value:
        logger.debug("Path [ %s ] exists", path)
    else:
        logger.debug("Path [ %s ] doesn't exist", path)

    return return_value


def get_stats_on_file(file_name):
    """Return the os.stat value for the specified filename, or None if it
    fails.

    :param file_name: The filename to get stat for
    :returns: an os.stat return value
    """
    logger.debug("Retrieving permission for file [ %s ] ", file_name)

    return_value = None
    try:
        return_value = os.stat(file_name)
    except OSError:
        logger.info("Stat for [ %s ] failed", file_name)
    else:
        logger.debug("Permissions: %s found for [ %s ]", return_value,
                     file_name)
    return return_value


def get_files_list_from_dir(base_path, subdirs=True, files_only=True):
    """Utility function used to find all descendants of a base path

    :param base_path: The main path to start looking from
    :param subdirs: True/False- Recurse through subdirectories?
    :param files_only: True/False- List directories?
    :returns:
    """
    return_list = None

    logger.debug("Listing files from directory [ %s ] ", base_path)

    if not check_path_exists(base_path):
        pass
    elif not os.path.isdir(base_path):
        logger.debug("Path [ %s ] is not a directory", base_path)
    else:
        # we have a directory, get all the files from it
        return_list = []
        for root, dirnames, filenames in os.walk(base_path):
            for filename in filenames:
                if root != base_path and not subdirs:
                    pass
                else:
                    return_list.append(root + '/' + filename)

            if not files_only:
                for dirname in dirnames:
                    return_list.append(root + '/' + dirname)

    return return_list


def get_sysctl_value(path):
    """Used to retrieve the value of a sysctl setting.  Uses a configurable
    base sysctl path. Raises a ValNotFound exception if the setting can't
    be retrieved for some reason.

    :param path: The path relative to base sysctl of the setting to retrieve
    :returns: The value of the specified sysctl setting
    """
    logger.debug("Testing for sysctl value [ %s ] ", path)

    # load sysctl_path from config if possible, otherwise grab default
    sysctl_path = config.get_config("paths.sysctl_path", constants.SYSCTL_PATH)

    value = None
    file_path = sysctl_path + "/" + path

    try:
        with open(file_path, 'r') as sysctl_file:
            value = sysctl_file.readline().strip()
    except IOError:
        logger.warning("Sysctl path [ %s ] not found", file_path)
        raise ValNotFound
    except EnvironmentError:
        logger.debug("Unable to read sysctl value [ %s ]", file_path)
        raise ValNotFound
    else:
        logger.debug("Value found: [ %s ] ", value)

    return value


def running_processes():
    """Use the /proc filesystem to determine a list of running processes.

    :returns: A list containing tuples of the pid of a running process
              and the executable file that launched it (if it exists).
    """
    procs = []
    for path in glob.glob('/proc/[0-9]*'):
        pid = int(os.path.basename(path))
        exe = None
        try:
            exe = os.path.realpath('/proc/{}/exe'.format(pid))
        except OSError:
            logger.debug("Unable to locate exe for [ %s ]", pid)
        procs.append((pid, exe))

    return procs


def is_service_running(service_name):
    """Use 'service <servicename> status' command to get the status of a
    service

    :returns: Boolean indicating if the service is running
    """

    service_command = ['service', service_name, 'status']
    service_running = False

    run_indicator = b'Active: active (running)'

    try:
        service_status = subprocess.check_output(service_command)

    # service command doesn't exist...
    except OSError:
        logger.error("Unable to call service command")

    except subprocess.CalledProcessError:
        # this indicates service is not running
        pass

    else:
        if run_indicator in service_status:
            service_running = True

    return service_running


def executables_in_path():
    """Search the current $PATH to create a list of all executable files

    :returns: A list of all executables on the $PATH
    """
    executables = []
    try:
        syspath = os.environ['PATH']
    except KeyError:
        logger.debug("$PATH variable not set.")
        return []

    for path in syspath.split(':'):
        for dirname, _, files in os.walk(path):
            executables.extend([os.path.join(path, f) for f in files])

    is_exec = lambda x: os.path.isfile(x) and os.access(x, os.X_OK)
    return [x for x in executables if is_exec(x)]


def listening_executables():
    """Search for executables of all running processes which have an open
    network socket

    :returns: A list of all network executables
    """

    executables = set()
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue

        listening = False

        fd_base = os.path.join('/proc', pid, 'fd')
        for fd in os.listdir(fd_base):
            try:
                fd_desc = os.readlink(os.path.join(fd_base, fd))
                if fd_desc.startswith('socket:'):
                    listening = True
                    break
            except OSError:
                # fds can disappear without warning, don't worry about it
                continue

        if listening:
            exe = os.readlink(os.path.join('/proc', pid, 'exe'))
            if exe.endswith(' (deleted)'):
                continue
            executables.add(exe)
    return sorted(executables)


def config_search(config_lines, config_descriptor, comment_delims=['#'],
                  keyval_delim=' '):
    """Find the option value specified by config_descriptor in config provided
    in config_lines.  If the file doesn't exist, will log an error and then
    re-raise the IOError exception.  If the option exists, return it, otherwise
    return None.
    :param config_lines: Lines of configuration file
    :param config_descriptor: String in the format 'section_header.value_name'
    :param comment_delims: (optional) list of characters which indicate a
    comment when seen at the beginning of the line
    :param keyval_delim: (optional) character which deliminates a key value
    separation

    :returns: Value of config setting if it exists, otherwise None
    """

    config_sections = defaultdict(dict)
    current_header = ''

    for line in config_lines:
        # strip spaces from the left, strip newline from the right
        stripped_line = line.lstrip(' ').strip()

        # if this is now an empty line, skip
        if len(stripped_line) < 1:
            pass

        # if this is a comment line, skip
        elif stripped_line[0] in comment_delims:
            pass

        # if this is a header line, set the header
        elif stripped_line[0] == '[':
            right_brace = stripped_line.find(']', 0)
            if right_brace != -1:
                current_header = stripped_line[1:right_brace]

        # otherwise this is a key value line
        else:
            # everything to the left of the keyval delimiter is the key, to
            # the right is the value
            keyval = stripped_line.split(keyval_delim, 1)
            key = keyval[0]

            # if there is no value, it's an empty string
            if len(keyval) > 1:
                value = keyval[1]
            else:
                value = ''

            config_sections[current_header][key] = value

    # search for the option specified in config descriptors
    config_descriptors = config_descriptor.split('.')

    # no section specified, look for the value in the '' section
    if len(config_descriptors) == 1:
        section = ''
        option = config_descriptors[0]

    elif len(config_descriptors) == 2:
        section = config_descriptors[0]
        option = config_descriptors[1]

    else:
        logger.error('Malformed config descriptor: [ %s ]', config_descriptor)
        return None

    try:
        return config_sections[section][option]
    except KeyError:
        return None


def have_command(cmd):
    """Returns true if the specified command is available on the system
    path.

    :param cmd: The command to check for using 'which'
    :returns: True if the supplied command is available on the path
    """
    try:
        null = open(os.devnull, 'w')
        rc = subprocess.check_call(['which', cmd], stdout=null, stderr=null)
        return rc == 0

    except subprocess.CalledProcessError:
        logger.debug("%s not on $PATH", cmd)

    return False


def get_flavor():
    """
    Returns the flavor listed in /etc/issue

    :returns: The Linux flavor in item[0] (if Debian/RH derivative)
    """
    try:
        file = open('/etc/issue', 'rb')
        item = file.readline().split()
    except IOError:
        return 'OTHER'
    file.close()

    if 'Debian' in item[0] or 'Ubuntu' in item[0] or 'hLinux' in item[0]:
        return 'DEB'
    elif 'RedHat' in item[0] or 'CentOS' in item[0]:
        return 'RH'


def kernel_version():
    """Return the kernel version information"""

    # equivalent to `uname -r`
    return os.uname()[2]


def kconfig():
    """ Return the contents of the kernel configuration"""
    paths = [
        '/proc/config.gz',
        '/boot/config-{}'.format(kernel_version()),
        '{}/.config'.format(os.getenv('KCONFIG_BUILD', '/usr/src/linux'))
    ]

    for path in paths:
        if os.path.exists(path):
            try:
                proc_config = gzip.open(path, 'r')
                return proc_config.read()

            except IOError:
                return open(path).read()


def kconfig_option(option, config=None):
    """Return the value of a kernel configuration option or None
    if it isn't set
    """
    if not config:
        config = kconfig()

    if not config:
        logger.info("Unable to find kernel config!")
        return None

    for line in config.split('\n'):
        if line.startswith('#'):
            continue
        parts = line.split("=")
        if len(parts) != 2:
            continue
        opt, val = parts
        if option == opt.strip():
            return val.strip()


def verify_config(config_name, config_lines, checked_options,
                  keyval_delim=' '):
    """Verify the given config lines against the following rules described by
    the checked_options parameter:

    - keys represent options names in the config file
    - options with "allowed" clause must be present
    - "allowed" options must have one of the listed values or any value in case
      of "allowed": "*"
    - options with "disallowed" options must not contain listed values
    - options with "disallowed": "*" must not be present at all
    - otherwise, they're allowed to be missing
    """
    return_results = []

    for option in checked_options:
        option_value = config_search(config_lines, option,
                                     keyval_delim=keyval_delim)

        test_name = "{}: '{}'".format(config_name, option)

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


def idempotent(f):
    """Cache the result of a function.

    Mark a function as idempotent. Its results will be cached for a given set
    of arguments. All future calls with the same arguments will be returned
    from cache.

    It's up to developers to guarantee that:
    - the result of an idempotent function is not changed in place (it will
      corrupt the cache)
    - all the arguments can be hashed
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        # create immutable versions of argument list
        ikwargs = tuple(sorted(kwargs.items()))
        cache_key = (args, ikwargs)

        cache = getattr(f, "_cache", {})
        if cache_key in cache:
            return cache[cache_key]

        res = f(*args, **kwargs)
        cache[cache_key] = res
        f._cache = cache
        return res

    return wrapper


@idempotent
def expand_openssl_ciphers(description):
    """Expand description to a list of SSL ciphers.

    Openssl allows providing a list of ciphers as names disabling/enabling
    specific encryption methods, or other attributes. For example
      openssl ciphers 'MD5+RC4:!aNULL'
    will expand to a list of ciphers using RC4 encryption with MD5 mac and
    remove ciphers with no authentication.

    This function will take a description like that and return an expanded list
    of ciphers which match the definition.
    """
    result = subprocess.check_output(['openssl', 'ciphers', description])
    return result.decode('ascii').split(':')


RE_SIG_ALGO = re.compile(b"Signature Algorithm: (\S+)")
RE_KEY_SIZE = re.compile(b"Public-Key: \(([0-9]+) bit\)")


def find_certificate_issues(path, purpose='sslserver'):
    """Verify certificate validity and sanity"""
    try:
        output = subprocess.check_output(['openssl', 'verify', '-x509_strict',
                                          '-purpose', purpose, path])
        if not output.strip().endswith(b": OK"):
            return "openssl verification failed"
    except OSError:
        return "openssl could not be executed"
    except subprocess.CalledProcessError:
        return "openssl verification failed"

    try:
        description = subprocess.check_output(['openssl', 'x509', '-text',
                                               '-noout', '-in', path])
    except subprocess.CalledProcessError:
        return "certificate parsing failed"

    for line in description.splitlines():
        line = line.strip()
        m = RE_SIG_ALGO.match(line)
        if m:
            if m.group(1) in ('sha1WithRSAEncryption', 'md5WithRSAEncryption'):
                return "weak signature algorithm"

        m = RE_KEY_SIZE.match(line)
        if m:
            key_size = int(m.group(1))
            if key_size < 2048:
                return "key size < 2048 bits"

    return None
