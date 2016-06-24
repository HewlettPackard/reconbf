import reconbf.lib.test_class as test_class
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import TestResult
from reconbf.lib.result import Result

import os
import platform


@test_class.explanation(
    """
    Protection name: Reboot required

    Check: Verify if the system thinks a reboot is required

    Purpose: Some distributions will report whether a reboot is
    required due to recently installed packages. This usually
    means a new binary cannot be easily restarted: like the
    kernel or the init system.
    """)
def reboot_required():
    try:
        distro, _version, _name = platform.linux_distribution()
    except Exception:
        return TestResult(Result.SKIP, "Could not detect distribution")

    if distro in ('Ubuntu', 'debian'):
        if os.path.isfile('/var/run/reboot-required'):
            try:
                with open('/var/run/reboot-required.pkgs', 'r') as f:
                    packages = set(line.strip() for line in f.readlines())
            except Exception:
                packages = None

            if packages:
                packages = ', '.join(sorted(packages))
                msg = "Reboot is required to update: %s" % packages
            else:
                msg = "Reboot is required"
            return TestResult(Result.FAIL, msg)

        else:
            return TestResult(Result.PASS)

    else:
        return TestResult(Result.SKIP, "Unknown distribution")


@test_class.explanation(
    """
    Protection name: Running processes have all corresponding files

    Check: Checks that each process running on the system uses
    files which are present on the disk.

    Purpose: Usually every running process will have the corresponding
    executable file and library available all the time. Anything
    different is an uncommon situation. It can happen for example
    because: file was deleted on purpose to avoid detection, package
    has been upgraded but the process was not restarted (potentially
    still vulnerable), etc.
    """)
def missing_process_binaries():
    results = GroupTestResult()

    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue

        try:
            main_binary = os.readlink(os.path.join('/proc', pid, 'exe'))

            missing_main = False
            missing = set()

            links = os.listdir(os.path.join('/proc', pid, 'map_files'))
            for link in links:
                link_path = os.readlink(os.path.join('/proc', pid, 'map_files',
                                                     link))
                if link_path.endswith(' (deleted)'):
                    if link_path == main_binary:
                        missing_main = True
                    else:
                        link_path = link_path[:-10]
                        # only check libraries, data files can go missing
                        # without issues
                        file_name = os.path.basename(link_path)
                        if file_name.endswith('.so') or '.so.' in file_name:
                            missing.add(link_path)

            if main_binary.endswith(' (deleted)'):
                main_binary = main_binary[:-10]

            process = "pid %s, %s" % (pid, main_binary)
            missing_list = []
            if missing_main:
                missing_list.append('main binary')
            missing_list.extend(sorted(missing))

            if missing_list:
                msg = "Missing: %s" % ', '.join(missing_list)
                results.add_result(process, TestResult(Result.FAIL, msg))
            else:
                results.add_result(process, TestResult(Result.PASS))

        except EnvironmentError:
            # this pid can disappear at any point, so on any read failure,
            # just continue with the next process
            continue

    return results
