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

from reconbf.lib.logger import logger
import reconbf.lib.test_class as test_class
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult
from reconbf.lib import utils

from subprocess import PIPE
from subprocess import Popen


def _conf_test_shellshock():
    return {"exploit_command":
            "env X='() { :;}; echo vulnerable' bash -c 'echo this is a test'"
            }


@test_class.takes_config(_conf_test_shellshock)
@test_class.explanation(
    """
    Protection name: Bash not vulnerable to shellshock

    Check: Runs shellshock test payload and validates output

    Purpose: A version of bash on the system which is vulnerable to shellshock
    can expose the system to many types of attacks.  There is no good way to
    take stock of how many processes running on they system use Bash in a
    potentially vulnerable way, so the only way to prevent exploitation is to
    use a version of bash which has been patched.
    """)
def test_shellshock(config):
    logger.debug("Testing shell for 'shellshock/bashbug' vulnerability.")

    try:
        cmd = config['exploit_command']
    except KeyError:
        logger.error("Can't find exploit command for shellshock test")
    else:

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()

        if b'vulnerable' in stdout:
            reason = "System is vulnerable to Shellshock/Bashbug."
            logger.info(reason)
            result = Result.FAIL
        else:
            reason = "System is not vulnerable to Shellshock/Bashbug."
            logger.info(reason)
            result = Result.PASS
        return TestResult(result, reason)


def _sysctl_report_failure(pattern, value):
    expected = "{} {}".format(pattern[0].replace("_", " "), pattern[1])
    return "expected {}, actual {}".format(expected, value)


def _sysctl_check(pattern, value):
    patt_type = pattern[0]
    if patt_type == "one_of":
        return value in pattern[1]

    elif patt_type == "none_of":
        return value not in pattern[1]

    elif patt_type == "match":
        return value == pattern[1]

    elif patt_type == "at_least":
        return int(value) >= int(pattern[1])

    else:
        raise ValueError("unknown pattern '{}'".format(patt_type))


def _sysctl_description(key, pattern):
    try:
        _, _, description = pattern
        return description
    except ValueError:
        return key


def _conf_test_sysctl_values():

    return {
        "fs/suid_dumpable": ("one_of", ["0", "2"], "SUID coredump handling"),
        "net/ipv4/tcp_syncookies": ("match", "1", "TCP syncookie protection"),
        "net/ipv4/tcp_max_syn_backlog": ("match", "4096"),
        "net/ipv4/conf/all/rp_filter": ("match", "1"),
        "net/ipv4/conf/all/accept_source_route": ("match", "0"),
        "net/ipv4/conf/all/accept_redirects": ("match", "0"),
        "net/ipv4/conf/all/secure_redirects": ("match", "0"),
        "net/ipv4/conf/default/accept_redirects": ("match", "0"),
        "net/ipv4/conf/default/secure_redirects": ("match", "0"),
        "net/ipv4/conf/all/send_redirects": ("match", "0"),
        "net/ipv4/conf/default/send_redirects": ("match", "0"),
        "net/ipv4/icmp_echo_ignore_broadcasts": ("match", "1"),
        "net/ipv4/icmp_ignore_bogus_error_responses": ("match", "1"),
        "net/ipv4/ip_forward": ("match", "0"),
        "net/ipv4/conf/all/log_martians": ("match", "1"),
        "net/ipv4/conf/default/rp_filter": ("match", "1"),
        "vm/swappiness": ("match", "0"),
        "vm/mmap_min_addr": ("one_of", ["4096", "8192", "16384", "32768",
                                        "65536", "131072"]),
        "kernel/core_pattern": ("match", "core"),
        "kernel/randomize_va_space": ("match", "2"),
        "kernel/exec-shield": ("match", "1"),
        "kernel/kptr_restrict": ("one_of", ["1", "2"],
                                 "Kernel pointer hiding"),

        # Affects kernels >= 3.6. Can be mitigated by setting
        # net.ipv4.tcp_challenge_act_limit to a large number.
        #
        # Proposed fix: https://github.com/torvalds/linux/commit/75ff39cc
        #
        # New default will be 1000, other recommendations are
        # 1073741823 (unsigned long long) and 999999999.
        #
        "net/ipv4/tcp_challenge_ack_limit":
            ("at_least", "1000", "CVE-2016-5696 challenge ack counter")
    }


@test_class.takes_config(_conf_test_sysctl_values)
@test_class.explanation(
    """
    Protection name: Sysctl settings set securely

    Check: Validates that sysctl values are set as specified in the
    configuration file.

    Purpose: Sysctl is used to configure kernel parameters. Many of these
    parameters can be used to tune and harden the security of a system. This
    check verifies that secure values have been used where applicable.
    """)
def test_sysctl_values(checks):
    results = GroupTestResult()

    if not checks:
        return TestResult(Result.SKIP, "Unable to load module config file")

    for key, pattern in checks.items():
        description = _sysctl_description(key, pattern)
        try:
            value = utils.get_sysctl_value(key)
            result = None
            if _sysctl_check(pattern, value):
                result = TestResult(Result.PASS)
            else:
                error = _sysctl_report_failure(pattern, value)
                result = TestResult(Result.FAIL, notes=error)

            results.add_result(description, result)

        except utils.ValNotFound:
            notes = "Could not find a value for {}".format(key)
            results.add_result(description,
                               TestResult(Result.SKIP, notes=notes))

    return results


@test_class.explanation("""
    Protection name: Certificate expiration check.

    Check: Run the command "openssl verify cer.pem" and ensure the
    stdout returns "OK" in the message.

    Purpose: Certificates create a level of trust between the system
    and the packages and pages that are signed with the certificates
    private key. Ensuring that these certificates are both not expired
    and are properly created certificiates will help confirm that
    whatever communication or package that is received is valid.
    """)
def test_certs():
    logger.debug("Testing bundled certificate validity & expiration.")

    certList = []
    certStore = '/etc/ssl/certs'
    result = None
    notes = ""

    # use utils to get list of certificates
    certList = utils.get_files_list_from_dir(certStore)

    if certList is None:
        notes = "/etc/ssl/certs is empty, please check on-system certificates."
        logger.debug(notes)
        result = Result.SKIP
        return TestResult(result, notes)

    for cert in certList:
        try:
            p = Popen(['openssl', 'verify', cert], stdout=PIPE, shell=False)
            stdout = p.communicate()
            if b"OK" in stdout[0]:
                logger.debug("Certificate verification success for: %s", cert)
                if result is None:
                    result = Result.PASS
            else:
                result = Result.FAIL
                if notes is "":
                    notes += "Error validating certificate: " + cert
                else:
                    notes += ", " + cert
                logger.debug("Certificate verification failure for: %s", cert)

        except ValueError:
            logger.exception("Error running 'openssl verify %s'", cert)
            result = Result.SKIP

    logger.debug("Completed on-system certificate validation tests.")
    return TestResult(result, notes)
