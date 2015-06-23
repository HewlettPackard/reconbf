import subprocess
import lib.test_class as test_class
from lib.test_result import Result
from lib.test_result import TestResult
import lib.test_utils as test_utils


def _get_docker_ps():
    """Takes the return of a get_ps_full() and strips out the cruft to
    only the docker config lines.

    :returns: A list containing any/all lines that have 'docker' in them.
    """

    process_list = test_utils.running_processes()
    docker_ps = []

    for entry in process_list:
        if entry[1] is not None:
            if 'docker' in entry[1]:
                docker_ps.append(subprocess.check_output(['ps',
                                                          '-o',
                                                          'cmd',
                                                          str(entry[0])]))

    return docker_ps


@test_class.explanation(
    """
    Protection name: Restrict communication between containers.

    Check: In a ps output, ensure the '--icc' parameter is set to 'false'.

    Purpose: Best practice is to filter communication between containers
    through the host so that it is not necessary to duplicate the filtering
    and controls already implemented at that level.
    """)
def test_traffic():
    logger = test_utils.get_logger()
    logger.debug("[*] Testing for restricted traffic between containers.")
    result = "No Docker containers found."

    docker_ps = _get_docker_ps()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")

    for entry in docker_ps:
        if '--icc=false' in entry:
            result = TestResult(Result.PASS)
        else:
            reason = "Direct communication between containers is enabled."
            result = TestResult(Result.FAIL, reason)

    return result


@test_class.explanation(
    """
    Protection name: Check Docker log level.

    Check: This check will look at the ps declaration to see if --log-level
    has been set there. If it is not it will look in the docker config files.
    In both cases it recommends info messages, and will warn on 'debug' level.

    Purpose: Good logging and auditing policies are general best-practice
    and it is not recommended to run at debug-level unless absolutely necessary
    both due to information collected and volume of events generated.
    """)
def test_log_level():
    logger = test_utils.get_logger()
    logger.debug("[*] Checking the Docker log level.")
    result = "No Docker containers found."

    # if --log-level is set in ps, else find config file and check there
    docker_ps = _get_docker_ps()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")

    for entry in docker_ps:
        if '--log-level=info' in entry:
            result = TestResult(Result.PASS)

        elif '--log-level=debug' in entry:
            reason = ("It is not recommended to run Docker in production "
                      "in debug mode.")
            result = TestResult(Result.FAIL, reason)

        else:
            logger.info("Recommended Docker log level is 'info'.")
            result = TestResult(Result.PASS)

    return result


@test_class.explanation(
    """
    Protection name: Delegate firewall rules to Docker-server.

    Check: This check will look at the ps declaration to see if the
    '--iptables' parameter is not present or set to false.

    Purpose: If a user-defined firewall is not implemented, the Docker-server
    will automatically make changes to the container firewalls as defined by
    the environment. However if a user manually sets a firewall rule, the
    Docker-server will no longer maintain the firewall rules.
    """)
def test_iptables():
    logger = test_utils.get_logger()
    logger.debug("[*] Checking the firewall settings.")
    result = "No Docker containers found."

    docker_ps = _get_docker_ps()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")
    for entry in docker_ps:
        if '--iptables=false' in entry:
            result = TestResult(Result.PASS)
        else:
            reason = ("The iptables firewall is enabled on a per-container "
                      "basis and will need to be maintained by the user.")
            result = TestResult(Result.FAIL, reason)

    return result


@test_class.explanation(
    """
    Protection name: Check for insecure registries.

    Check: The output of a ps command will contain the --insecure-registry flag

    Purpose: Registries that are specified with the --insecure-registry flag
    are remote and ignoring any security checks that Docker builds in. This
    is not best practice, and these images should be stored in a local registry
    with proper integrity, communication, and validation controls applied.
    """)
def test_insecure_registries():
    logger = test_utils.get_logger()
    logger.debug("[*] Testing for insecure registries.")
    result = "No Docker containers found."

    docker_ps = _get_docker_ps()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")

    for entry in docker_ps:
        if '--insecure-registry' in entry:
            reason = ("A registry was specified with the --insecure-registry "
                      "flag.")
            result = TestResult(Result.FAIL, reason)
        else:
            result = TestResult(Result.PASS)

    return result


@test_class.explanation(
    """
    Protection name: Test for socket/port binding.

    Check: This checks looks at the output of a ps for the -H flag.

    Purpose: The -H flag will bind to a specific interface or port on a
    system. This can interfere with other processes or applications
    using this interface or port and should not be used.
    """)
def test_port_binding():
    logger = test_utils.get_logger()
    logger.debug("[*] Testing for insecure registries.")
    result = "No Docker containers found."

    docker_ps = _get_docker_ps()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")

    for entry in docker_ps:
        if '-H' in entry:
            reason = ("A container is binding to a specific interface "
                      "or port.")
            result = TestResult(Result.FAIL, reason)
        else:
            result = TestResult(Result.PASS)

    return result


@test_class.explanation(
    """
    Protection name: Validate secure communication.

    Check: This check looks at the ps output for several --tls* options:
    --tlsverify - this option ensures validation of TLS certificates
    --tlscacert - this option specifies a certificate from a CA
    --tlscert   - checks for the existence of a host certificate
    --tlskey    - checks for the corresponding private key from a host cert

    Purpose: This will check for the ability to communicate securely, across
    multiple roles.
    """)
def test_secure_communication():
    # TODO: check if there is a 'well known' HDP container that either
    # acts as an intermediate CA (for --tlscacert option), or a server
    # that clients connect to securely (for --tlscert and tlskey), and
    # if so, break them into separate tests for better profile coverage

    logger = test_utils.get_logger()
    logger.debug("[*] Testing for insecure registries.")
    result = "No Docker containers found."

    docker_ps = _get_docker_ps()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")

    for entry in docker_ps:
        if '--tlsverify' in entry:
            if '--tlscert' in entry:
                if '--tlskey' in entry:
                    if '--tlscacert' in entry:
                        reason = ("Container set to validate certificates, "
                                  "has both certificate and key in place, "
                                  "and can act as an intermediate CA.")
                        logger.info("[+] " + reason)
                    else:
                        reason = ("No CA certificate, container cannot act "
                                  "as intermediate CA.")
                        logger.info("[-] " + reason)
                else:
                    reason = ("A public Certificate exists, but key does not."
                              " Communciation unable to be decrypted.")
                    logger.info("[-] " + reason)

            else:
                reason = ("No certificate available, container will only be"
                          " able to act as client and accept server cert.")

        else:
            reason = "Docker is not configured to validate certificates."
            result = TestResult(Result.FAIL, reason)
            return result

    result = TestResult(Result.PASS)

    return result


@test_class.explanation(
    """
    Protection name: Check if Docker is running inside LXC memory space.

    Check: Look at the ps to ensure no occurrence of lxc exists.

    Purpose: Docker was originally built inside LXC userspace, but has now
    extended outside of it, so both from a legacy and controls perspective
    it should be outside there.
    """)
def test_no_lxc():
    logger = test_utils.get_logger()
    logger.debug("[*] Testing .")
    result = "No Docker containers found."

    docker_ps = _get_docker_ps()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")

    for entry in docker_ps:
        if 'lxc' in entry:
            reason = "LXC in ps output."
            result = TestResult(Result.FAIL, reason)
        else:
            result = TestResult(Result.PASS)

    return result
