import subprocess
import lib.test_class as test_class
from lib.test_result import Result
from lib.test_result import TestResult
import lib.test_utils as test_utils


def _get_docker_processes():
    """Takes the return of a get_ps_full() and strips out the cruft to
    only the docker config lines.

    :returns: A list containing any/all lines that have 'docker' in them.
    """

    process_list = test_utils.running_processes()
    docker_ps = []

    for entry in process_list:
        if entry[1]:
            if 'docker' in entry[1]:
                results = subprocess.check_output(['ps',
                                                   '-o',
                                                   'cmd',
                                                   str(entry[0])])
                # ps -o returns the heading 'CMD', so pop that off
                results.pop(0)
                docker_ps.append(results)

    return docker_ps


def _get_docker_ps():
    """Runs the docker ps command.

    :returns: The output of the docker ps command (minus heading).
    """

    containers = []
    containers = subprocess.check_output(['docker', 'ps']).split('\n')
    # docker ps command returns column headings, so pop those off
    containers.pop(0)

    return containers


def _get_docker_info():
    """Runs the docker info command.

    :returns: Information about the docker installation including storage,
    kernel, os, and initpath information.
    """

    return subprocess.check_output(['docker', 'info'])


def _get_docker_inspect(container_id):
    """Runs the docker inspect command.

    :returns: JSON-formatted information about the container passed.
    """

    return subprocess.check_output(['docker', 'inspect', container_id])


def _parse_colon_delim(list, key=''):
    """Parses a colon-delimeted list (such as docker-info) into a dict
    of key, value pairs.

    :returns: If key is specified, the list is searched for the
    corresponding value. If a key is not specified, a dict of both the
    collective keys and values is returned.
    """

    conf = {}

    for item in list:
        k, v = item.split(':').strip()
        if key:
            if k == key:
                return v
        else:
            conf[k] = v

    return conf


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
    reason = "No Docker containers found."

    result = None

    docker_ps = _get_docker_processes()
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
    reason = "No Docker containers found."

    result = None

    # if --log-level is set in ps, else find config file and check there
    docker_ps = _get_docker_processes()
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
    reason = "No Docker containers found."

    result = None

    docker_ps = _get_docker_processes()
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
    reason = "No Docker containers found."

    result = None

    docker_ps = _get_docker_processes()
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
    reason = "No Docker containers found."

    result = None

    docker_ps = _get_docker_processes()
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
    reason = "No Docker containers found."

    docker_ps = _get_docker_processes()
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
    logger.debug("[*] Testing if the container is running in LXC memory.")
    reason = "No Docker containers found."

    result = None

    docker_ps = _get_docker_processes()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")

    for entry in docker_ps:
        if 'lxc' in entry:
            reason = "LXC in ps output."
            result = TestResult(Result.FAIL, reason)
        else:
            result = TestResult(Result.PASS)

    return result


@test_class.explanation(
    """
    Protection name: Ensure container is running in user namespace.

    Check: From the output of 'docker ps' use the id to inspect the container
    user.

    Purpose: Validating the container is running in user namespace ensures
    that memory used by the container is not being used by root.
    """)
def test_user_owned():
    logger = test_utils.get_logger()
    logger.debug("[*] Testing if the container is running in user namespace.")
    reason = "No Docker containers found."

    containers = _get_docker_ps()
    if containers is None:
        return TestResult(Result.SKIP, reason)

    for line in containers:
        container_id = line.split(' ')

    for instance in container_id[0]:
        results = subprocess.check_output(['docker',
                                           'inspect',
                                           '--format',
                                           '{{.ID}}:{{.Config.User}}',
                                           instance])
        container_id = results.split(':')
        if container_id[1] is None:
            reason = ("Container " + str(container_id[0]) + " is running in "
                      "root namespace.")
            return TestResult(Result.FAIL, reason)
        else:
            return TestResult(Result.PASS)


@test_class.explanation(
    """
    Protection name: List installed packages.

    Check: This check will list all of the packages installed in a container.

    Purpose: Best practice is to install as few packages as possible to
    decrease the amount of additional processes, open ports, and other
    items that could be used to compromise a system.
    """)
def test_list_installed_packages():
    logger = test_utils.get_logger()
    logger.debug("[*] Listing installed packages.")
    reason = "No Docker containers found."

    containers = _get_docker_ps()
    if containers is None:
        return TestResult(Result.SKIP, reason)

    for line in containers:
        container_id = line.split(' ')

    for instance in container_id[0]:
        flavor = subprocess.check_output(['docker',
                                          'exec',
                                          instance,
                                          'cat',
                                          '/etc/issue'])
        if 'RH' in flavor:
            notes = subprocess.check_output(['docker',
                                             'exec',
                                             instance,
                                             'rpm',
                                             '-qa']).split('\n')
        elif 'DEB' in flavor:
            notes = subprocess.check_output(['docker',
                                             'exec',
                                             instance,
                                             'dpkg',
                                             '-l']).split('\n')
        else:
            reason = "Host is not RedHat or Debian family."
            return TestResult(Result.SKIP, reason)

    return TestResult(Result.PASS, notes)


@test_class.explanation(
    """
    Protection name: Check storage driver.

    Check: This check will ensure the storage driver isn't aufs.

    Purpose: The aufs driver is insecure and allows a process to escape
    the container. As such it should not be used.
    """)
def test_storage_driver():
    logger = test_utils.get_logger()
    logger.debug("[*] Checking storage driver.")
    notes = "No Docker containers found."

    driver = _parse_colon_delim(list, key='Storage Driver')

    if driver:
        if 'aufs' in driver:
            notes = "Storage driver set to insecure aufs."
            return TestResult(Result.FAIL, notes)
        else:
            return TestResult(Result.PASS)
    else:
        # empty driver, odd failure
        return TestResult(Result.SKIP, notes)


@test_class.explanation(
    """
    Protection name: Audit Docker daemon

    Check: Look through the output of the auditctl command for an entry
    for /usr/bin/docker to show the process is being managed by the
    kernel audit system

    Purpose: Auditctl is a "Controlled Access Protection Profiles"
    framework that helps gather information about system events. These
    are managed by the auditctl policy, and ensuring the Docker daemon
    is included in these checks will help monitoring of a Docker
    environment. Check is only valid for pre-3.11 kernels.
    """)
def test_docker_daemon():
    logger = test_utils.get_logger()
    logger.debug("[*] Checking auditing on the Docker daemon.")
    note = "Test is invalid for newer kernels."

    kernel = subprocess.check_output(['uname', '-r'])
    major_version = kernel[0]
    minor_version = int(kernel[2:3])
    if "3" in major_version:
        if minor_version >= 12:
            return TestResult(Result.SKIP, note)

    if subprocess.check_output(['whereis', 'auditctl']):
        audit = subprocess.check_output(['auditctl', '-l'])
        if '/usr/bin/docker' in audit:
            return TestResult(Result.PASS)
        else:
            note = "/usr/bin/docker is not being tracked in auditctl."
            return TestResult(Result.FAIL, note)
    else:
        note = "The auditctl command is not installed."
        return TestResult(Result.FAIL, note)
