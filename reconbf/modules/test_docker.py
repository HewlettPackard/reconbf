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
import json
import os
import subprocess
import reconbf.lib.test_class as test_class
from reconbf.lib.result import Result, GroupTestResult, TestResult
from reconbf.lib import utils


@utils.idempotent
def _get_main_docker_processes():
    """Find all processes with the binary named "dockerd".
    """

    process_list = utils.running_processes()
    docker_ps = []

    for entry in process_list:
        cmdline = utils.cmdline_for_pid(entry[0])
        binary = cmdline[0]
        bin_base = os.path.basename(binary)
        if bin_base == b'dockerd' or (bin_base == b'docker' and
                                      len(cmdline) >= 2 and
                                      cmdline[1] == b'daemon'):
            docker_ps.append((entry[0], cmdline))

    return docker_ps


# TODO: deprecated, delete after moving to _get_main_docker_process
def _get_docker_processes():
    """Takes the return of a get_ps_full() and strips out the cruft to
    only the docker config lines.

    :returns: A list containing any/all lines that have 'docker' in them.
    """

    process_list = utils.running_processes()
    docker_ps = []

    for entry in process_list:
        if entry[1]:
            if 'docker' in entry[1]:
                results = subprocess.check_output(['ps',
                                                   '-o',
                                                   'cmd',
                                                   str(entry[0])])
                # ps -o returns the heading 'CMD', so pop that off
                results_list = results.split(b'\n')
                results_list.pop(0)
                docker_ps.append(results)

    return docker_ps


@utils.idempotent
def _get_docker_container():
    """Runs the docker ps -q command.

    :returns: The output of the docker ps command (minus heading).
    """
    containers = []
    try:
        containers = subprocess.check_output(['docker',
                                              'ps',
                                              '-q']).split(b'\n')
    except subprocess.CalledProcessError:
        return None

    return [c for c in containers if c]


def _get_docker_info():
    """Runs the docker info command.

    :returns: Information about the docker installation including storage,
    kernel, os, and initpath information.
    """

    try:
        return subprocess.check_output(['docker', 'info'])
    except subprocess.CalledProcessError:
        return None


@utils.idempotent
def _get_docker_inspect(container_id):
    """Runs the docker inspect command.

    :returns: JSON-formatted information about the container passed.
    """

    inspect = subprocess.check_output(['docker', 'inspect', container_id])
    return json.loads(inspect)[0]


@test_class.explanation(
    """
    Protection name: Restrict communication between containers.

    Check: In a ps output, ensure the '--icc' parameter is set to 'false'.

    Purpose: Best practice is to filter communication between containers
    through the host so that it is not necessary to duplicate the filtering
    and controls already implemented at that level.
    """)
def test_traffic():
    logger.debug("Testing for restricted traffic between containers.")

    dockers = _get_main_docker_processes()
    if not dockers:
        return TestResult(Result.SKIP, "Docker is not running.")

    results = GroupTestResult()
    for pid, cmdline in dockers:
        if '--icc=false' in cmdline:
            results.add_result("pid %s" % pid, TestResult(Result.PASS))
        else:
            reason = "Direct communication between containers is enabled."
            results.add_result("pid %s" % pid, TestResult(Result.FAIL, reason))

    return results


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
    logger.debug("Checking the Docker log level.")

    # if --log-level is set in ps, else find config file and check there
    dockers = _get_main_docker_processes()
    if not dockers:
        return TestResult(Result.SKIP, "Docker is not running.")

    results = GroupTestResult()
    for pid, cmdline in dockers:
        if '--log-level=info' in cmdline:
            results.add_result("pid %s" % pid, TestResult(Result.PASS))

        elif '--log-level=debug' in cmdline:
            reason = ("It is not recommended to run Docker in production "
                      "in debug mode.")
            results.add_result("pid %s" % pid, TestResult(Result.FAIL, reason))

        else:
            notes = "Recommended Docker log level is 'info'."
            results.add_result("pid %s" % pid, TestResult(Result.PASS, notes))

    return results


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
    logger.debug("Checking the firewall settings.")

    dockers = _get_main_docker_processes()
    if not dockers:
        return TestResult(Result.SKIP, "Docker is not running.")

    results = GroupTestResult()
    for pid, cmdline in dockers:
        if '--iptables=false' in cmdline:
            results.add_result("pid %s" % pid, TestResult(Result.PASS))
        else:
            reason = ("The iptables firewall is enabled on a per-container "
                      "basis and will need to be maintained by the user.")
            results.add_result("pid %s" % pid, TestResult(Result.FAIL, reason))

    return results


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
    logger.debug("Testing for insecure registries.")

    dockers = _get_main_docker_processes()
    if not dockers:
        return TestResult(Result.SKIP, "Docker is not running.")

    results = GroupTestResult()
    for pid, cmdline in dockers:
        if '--insecure-registry' in cmdline:
            reason = ("A registry was specified with the --insecure-registry "
                      "flag.")
            results.add_result("pid %s" % pid, TestResult(Result.FAIL, reason))
        else:
            results.add_result("pid %s" % pid, TestResult(Result.PASS))

    return results


@test_class.explanation(
    """
    Protection name: Test for socket/port binding.

    Check: This checks looks at the output of a ps for the -H flag.

    Purpose: The -H flag will bind to a specific interface or port on a
    system. This can interfere with other processes or applications
    using this interface or port and should not be used.
    """)
def test_port_binding():
    logger.debug("Testing for insecure registries.")

    dockers = _get_main_docker_processes()
    if not dockers:
        return TestResult(Result.SKIP, "Docker is not running.")

    results = GroupTestResult()
    for pid, cmdline in dockers:
        if '-H' in cmdline:
            reason = ("A container is binding to a specific interface "
                      "or port.")
            results.add_result("pid %s" % pid, TestResult(Result.FAIL, reason))
        else:
            results.add_result("pid %s" % pid, TestResult(Result.PASS))

    return results


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

    logger.debug("Testing for insecure registries.")

    docker_ps = _get_docker_processes()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")

    for entry in docker_ps:
        if b'--tlsverify' in entry:
            if b'--tlscert' in entry:
                if b'--tlskey' in entry:
                    if b'--tlscacert' in entry:
                        reason = ("Container set to validate certificates, "
                                  "has both certificate and key in place, "
                                  "and can act as an intermediate CA.")
                        logger.info(reason)
                    else:
                        reason = ("No CA certificate, container cannot act "
                                  "as intermediate CA.")
                        logger.info(reason)
                else:
                    reason = ("A public Certificate exists, but key does not."
                              " Communciation unable to be decrypted.")
                    logger.info(reason)

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
    logger.debug("Testing if the container is running in LXC memory.")
    reason = "No Docker containers found."

    result = None

    docker_ps = _get_docker_processes()
    if docker_ps is None:
        return TestResult(Result.SKIP, "Docker is not running.")

    for entry in docker_ps:
        if b'lxc' in entry:
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
    logger.debug("Testing if the container is running in user namespace.")
    reason = "No Docker containers found."

    containers = _get_docker_container()
    if not containers:
        return TestResult(Result.SKIP, reason)

    results = GroupTestResult()

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        user = inspect.get("Config", {}).get("User")
        check = "container " + str(container_id)

        if not user:
            reason = ("Container is running in root namespace.")
            results.add_result(check, TestResult(Result.FAIL, reason))
        else:
            results.add_result(check, TestResult(Result.PASS))

    return results


@test_class.explanation(
    """
    Protection name: List installed packages.

    Check: This check will list all of the packages installed in a container.

    Purpose: Best practice is to install as few packages as possible to
    decrease the amount of additional processes, open ports, and other
    items that could be used to compromise a system.
    """)
def test_list_installed_packages():
    logger.debug("Listing installed packages.")
    notes = ""

    containers = _get_docker_container()
    if not containers:
        reason = "No Docker containers found."
        return TestResult(Result.SKIP, reason)

    for instance in containers:
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
                                             '-qa']).split(b'\n')
        elif 'DEB' in flavor:
            notes = subprocess.check_output(['docker',
                                             'exec',
                                             instance,
                                             'dpkg',
                                             '-l']).split(b'\n')
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
    logger.debug("Checking storage driver.")

    info = _get_docker_info()
    if not info:
        return TestResult(Result.SKIP, "Cannot get docker info.")
    driver = [l for l in info.splitlines()
              if l.startswith(b'Storage Driver:')]

    if driver:
        if 'aufs' in driver[0]:
            notes = "Storage driver set to insecure aufs."
            return TestResult(Result.FAIL, notes)
        else:
            return TestResult(Result.PASS)
    else:
        # empty driver, odd failure
        return TestResult(Result.SKIP, "Cannot find storage driver")


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
    logger.debug("Checking auditing on the Docker daemon.")
    note = "Test is invalid for newer kernels."

    kernel = os.uname()[2].split('.')
    major_version = kernel[0]
    minor_version = int(kernel[1])
    if "3" in major_version:
        if minor_version >= 12:
            return TestResult(Result.SKIP, note)

    try:
        subprocess.check_output(['which', 'auditctl'])
    except subprocess.CalledProcessError:
        note = "The auditctl command is not installed."
        return TestResult(Result.SKIP, note)

    audit = subprocess.check_output(['auditctl', '-l'])
    if b'/usr/bin/docker' in audit:
        return TestResult(Result.PASS)
    else:
        note = "/usr/bin/docker is not being tracked in auditctl."
        return TestResult(Result.FAIL, note)


@test_class.explanation(
    """
    Protection name: Privileged container checks

    Check: Check to ensure that privileged containers
    are not being used.

    Purpose: The --privileged flag gives all capabilities
    to the container, and it also lifts all the limitations
    enforced by the device cgroup controller. If this flag is
    set to true, this presents a vulnerability as this flag allows
    the container can then do almost everything that the host can do.
    """)
def test_docker_privilege():
    logger.debug("Testing if the container is running in user namespace.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        privileged = inspect.get("HostConfig", {}).get("Privileged")
        check = "container " + str(container_id)

        if not privileged:
            result = TestResult(Result.PASS)
        else:
            notes = "Container is running with privileged flags set to true."
            result = TestResult(Result.FAIL, notes)
        results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Container memory limitations.

    Check: Checks to ensure that memory limitations are set.

    Purpose: If memory limitations are not set this can cause an
    inadvertant Denial of Service for the host machine as docker can
    use all of the allotted memory given to a host machine.
    """)
def test_memory_limit():
    logger.debug("Testing if the container has memory limitations.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        check = "container " + str(container_id)
        inspect = _get_docker_inspect(container_id)
        memory = inspect.get("HostConfig", {}).get("Memory")
        if memory is None:
            result = TestResult(Result.SKIP, "Memory limit cannot be found")
        elif memory <= 0:
            result = TestResult(Result.FAIL, "No memory limit set")
        else:
            result = TestResult(Result.PASS)
        results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Priviledge port mapping.

    Check: Containers should not use port numbers with
    a value above 1024.

    Purpose: If port numbers above 1024 are utilized the
    users run the risk of ability to receive and transmit
    various sensitive and privileged data. Allowing containers
    to use them can bring serious implications.
    """)
def test_privilege_port_mapping():
    logger.debug("Testing if the container has memory limitations.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        if container_id == '':
            pass
        else:
            check = "container " + str(container_id)
            test = subprocess.check_output(['docker',
                                            'port',
                                            container_id])
            pn = test.split(b':')
            try:
                port_number = str(pn[1])
            except IndexError:
                notes = ("Container: " + str(container_id) + "returns "
                         "a malformed port number value.")
                result = TestResult(Result.SKIP, notes)
            else:
                if int(port_number) <= 1024:
                    notes = ("Container " + str(container_id) + " is running "
                             "privileged port number - " + str(port_number) +
                             ".")
                    result = TestResult(Result.FAIL, notes)
                elif port_number == '':
                    notes = ("Container " + str(container_id) + " does not"
                             "have a port number assigned.")
                    result = TestResult(Result.FAIL, notes)
                elif port_number is None:
                    notes = ("Container " + str(container_id) + " does not"
                             "have a port number assigned.")
                    result = TestResult(Result.FAIL, notes)
                else:
                    result = TestResult(Result.PASS)
            results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Network Mode value.

    Check: Containers should not use "host" Network
    Mode.

    Purpose: If Network Mode is set to host there is the
    potential that containers will be allowing processes
    to open low-numbered ports like any other root process.
    """)
def test_host_network_mode():
    logger.debug("Testing if the container is running in user namespace.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        net_mode = inspect.get("HostConfig", {}).get("NetworkMode")
        check = "container " + str(container_id)

        if net_mode != 'host':
            result = TestResult(Result.PASS)
        else:
            notes = "Container is running in host Network Mode."
            result = TestResult(Result.FAIL, notes)
        results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Check CPU priority settings.

    Check: Containers should be checked that CPU priority
    is set appropriately.

    Purpose: If a return of 0 or 1024 is given, it means
    the CPU shares are not in place. Some containers may
    require more CPU allocation than others therefore not
    setting shares could lead to an inadvertant Denial of
    Service.
    """)
def test_cpu_priority():
    logger.debug("Testing if the container has memory limitations.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        shares = inspect.get("HostConfig", {}).get("CpuShares", 1024)
        check = "container " + str(container_id)

        if not shares or shares == 1024:
            notes = "Container do not have CPU shares in place."
            result = TestResult(Result.FAIL, notes)
        else:
            result = TestResult(Result.PASS)
        results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Read only root file system.

    Check: Check to ensure that container's root filesystem
    is mounted as read only.

    Purpose: Data should not be written within containers. The
    data volume belonging to a container should be explicitly
    defined and administered.
    """)
def test_read_only_root_fs():
    logger.debug("Testing if the container is running in user namespace.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        readonly = inspect.get("HostConfig", {}).get("ReadonlyRootfs", False)
        check = "container " + str(container_id)

        if readonly:
            result = TestResult(Result.PASS)
        else:
            notes = "Container uses a root filesystem which is not read only."
            result = TestResult(Result.FAIL, notes)
        results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Limit container restart tries.

    Check: Check to ensure that container's restart policy settings
    are set appropriately.

    Purpose: If you indefinitely keep trying to start the container,
    it could possibly lead to a denial of service on the host, therefore
    tries to restart the container should be set to no more than 5. If a
    container's value is set to 'RestartPolicyName=no' or just 'RestartPolicy
    Name=' this is considered compliant as the container will never attempt to
    restart.
    """)
def test_restart_policy():
    logger.debug("Testing if the container is running in user namespace.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        policy_name = inspect.get("HostConfig", {}).get(
            "RestartPolicy", {}).get("Name")
        max_retry = inspect.get("HostConfig", {}).get(
            "RestartPolicy", {}).get("MaximumRetryCount")
        check = "container " + str(container_id)

        if policy_name == 'no':
            result = TestResult(Result.PASS)
        elif policy_name is None:
            result = TestResult(Result.PASS)
        elif policy_name == 'always':
            notes = ("Container will always restart regardless of max retry "
                     "count. This is not recommended.")
            result = TestResult(Result.FAIL, notes)
        elif policy_name == 'on-failure':
            if int(max_retry) <= 5:
                result = TestResult(Result.PASS)
            else:
                notes = "Container max retry count set to a high level."
                result = TestResult(Result.FAIL, notes)
        else:
            notes = "Unknown restart policy."
            result = TestResult(Result.SKIP, notes)
        results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Host process namespace sharing

    Check: Check that containers are not sharing host
    process namespaces.

    Purpose: If host process namespaces are being shared with
    containers it would allow processes within the container
    to see all of the processes on the host system. Thus breaking
    the benefit of process level isolation between the host and
    the containers.
    """)
def test_docker_pid_mode():
    logger.debug("Testing if the container is running in user namespace.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        pid_mode = inspect.get("HostConfig", {}).get("PidMode")
        check = "container " + str(container_id)

        if pid_mode == 'host':
            notes = "Container is sharing host process namespaces."
            result = TestResult(Result.FAIL, notes)
        else:
            result = TestResult(Result.PASS)

        results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Sensitive host system directories

    Check: Check that containers are not mounting sensitive
    host system directories on containers.

    Purpose: If sensitive directories are mounted in read-write mode,
    it would be possible to make changes to files within those sensitive
    directories. The changes might bring down security implications or
    unwarranted changes that could put the Docker host in compromised
    state.
    """)
def test_mount_sensitive_directories():
    logger.debug("Testing if the container is running in user namespace.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        binds = inspect.get("HostConfig", {}).get("Binds") or []
        check = "container " + str(container_id)

        result = TestResult(Result.PASS)
        for bind in binds:
            parts = bind.split(':')
            src = parts[0]
            opts = parts[-1] if len(parts) > 2 else None
            rw = bool(opts) and ('rw' in opts)

            if (src.startswith('/usr') or src.startswith('/etc') or
                    src.startswith('/bin') or src.startswith('/boot')):
                notes = ("Container has sensitive host system directories "
                         "mounted read-write: %s" % src)
                result = TestResult(Result.FAIL, notes)
                break

        results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Host IPC namespace

    Check: Check that containers are not sharing namespaces with
    host IPCs.

    Purpose: IPC namespace provides separation of IPC between the host and
    containers. If the host's IPC namespace is shared with the container, it
    would basically allow processes within the container to see all of the
    IPC on the host system.
    """)
def test_IPC_host():
    logger.debug("Testing if the container is running in user namespace.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        ipc_mode = inspect.get("HostConfig", {}).get("IpcMode")
        check = "container " + str(container_id)

        if ipc_mode == 'host':
            notes = "Container is sharing IPC namespace with the host."
            result = TestResult(Result.FAIL, notes)
        else:
            result = TestResult(Result.PASS)

        results.add_result(check, result)
    return results


@test_class.explanation(
    """
    Protection name: Ulimit default override

    Check: Check that containers are not running with ulimit
    defaults.

    Purpose: Ulimit provides control over the resources
    available to the shell and to processes started by it.
    Setting system resource limits judiciously saves you from
    many vulnerabilities such as a fork bomb.
    """)
def test_ulimit_default_override():
    logger.debug("Testing if the container is running in user namespace.")
    notes = "No Docker containers found or docker is not running."

    results = GroupTestResult()

    containers = _get_docker_container()

    if not containers:
        return TestResult(Result.SKIP, notes)

    for container_id in containers:
        inspect = _get_docker_inspect(container_id)
        ulimits = inspect.get("HostConfig", {}).get("Ulimits")
        check = "container " + str(container_id)

        if ulimits is None:
            notes = "Container is running with default ulimits in place."
            result = TestResult(Result.FAIL, notes)
        else:
            result = TestResult(Result.PASS)

        results.add_result(check, result)
    return results
