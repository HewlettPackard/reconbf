import lib.test_class as test_class
from lib.test_result import TestResult
from lib.test_result import Result
import subprocess as s


@test_class.explanation(
    """
    Protection name: Default DNS domain name check.

    Check: Ensures that a default domain name is set.

    Purpose: A default hostname should be set in the
    /etc/hostname file, so that traffic can be routed
    to the proper host. In the event that a hostname is
    not set a user set this information which allows for
    possibly intercept and manipulate traffic or other
    types of malicious behavior on the local network.
    """)
def test_dns_name():
    try:
        host = s.check_output('hostname')
    except OSError:
        return TestResult(Result.SKIP, notes='Unable to find hostname.')

    if host is not "":
        result = Result.PASS
        notes = 'Default hostname is ' + host.replace("\n", "") + '.'
    else:
        result = Result.FAIL
        notes = 'Hostname is empty!'
    return TestResult(result, notes)


@test_class.explanation(
    """
    Protection name: Default DNS search domain check.

    Check: Ensures that an entry exists in /etc/resolv.conf
    for default DNS search domain.

    Purpose: Domain Name System (DNS) search domains should be
    set in the /etc/resolv.conf file as missing information can
    lead to potential exploitation such as insertion of entries
    that would result in name resolution requests to be serviced
    by a rogue DNS.
    """)
def test_default_dns_search():
    text = 'search '
    try:
        fp = open('/etc/resolv.conf', 'r')
    except IOError:
        return TestResult(Result.SKIP, notes="File /etc/resolv.conf " +
                                             "can't be opened for reading!")

    f = fp.read()

    if f.find(text):
        result = Result.PASS
        notes = 'Default search domain exists.'
    else:
        result = Result.FAIL
        notes = 'Default search domain does not exist!'
    return TestResult(result, notes)

    fp.close()
