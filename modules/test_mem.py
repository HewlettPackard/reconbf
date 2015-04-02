import lib.test_utils as test_utils
import lib.test_class as test_class
from lib.test_result import TestResult
from lib.test_result import Result
from subprocess import Popen, PIPE, check_output
import gzip

@test_class.tag("software", "system", "kernel")
@test_class.explanation(
    """
    Protection name: NX (No-eXecute) protection is enabled
    Check: First line in the system dmesg indicates if it is enabled
    Purpose: The NX bit indicates if the architecture has marked
    specific areas of memory as non-executable (known as executable
    space protection) and helps preventing certain types of buffer
    overflow attacks.
    """)
def test_NX():
    logger = test_utils.get_logger()
    result = " "
    logger.debug("[*] Checking if NX (or NX emulation) is present.")

    try:
        output = check_output(["dmesg"])
        if 'NX (Execute Disable) protection: active' in output:
            reason = "NX protection active in BIOS."
            logger.debug("[+]" + reason)
            result = Result.PASS

        else:
            # not active
            reason = "NX protection disabled in BIOS."
            logger.debug("[-]" + reason)
            result = Result.FAIL

    return TestResult(result, reason)


@test_class.tag("system", "kernel", "memory")
@test_class.explanation(
    """
    Protection: /dev/mem device blocks non-device access
    Check: in /proc/config.gz the CONFIG_STRICT_DEVMEM line is
    uncommented and set to equal 'y'
    Purpose: Some applications are built to require access to physical
    memory in the user-space (such as X windows), which was provided
    by the /dev/mem device. This check ensures that only other devices
    have access to the kernel memory, and thus does not allow a 
    malicious user or program the ability to view or change data.
    """)
def test_devmem():
    # initial configurations
    reason = " "
    logger = test_utils.get_logger()
    logger.debug("[*] Attempting to validate /dev/mem protection.")
    result = Result.FAIL # set fail by default?

    # check /proc/config.gz - CONFIG_STRICT_DEVMEM=y
    try:
        proc_config = gzip.open('/proc/config.gz','rb')
        kernel_cfg = proc_config.read()

        if "CONFIG_STRICT_DEVMEM=y" in kernel_cfg:
            reason = "/dev/mem protection is enabled."
            logger.debug("[+] " + reason)
            result = Result.PASS
        elif "CONFIG_STRICT_DEVMEM=n" in kernel_cfg:
            reason = "/dev/mem protection is not enabled."
            logger.debug("[-] "+ reason)
            result = Result.FAIL

    except IOError as e:
        reason = "Error opening /proc/config.gz."
        logger.debug("[*] Unable to open /proc/config.gz.")
        logger.debug("    Exception information: {")
        logger.debug(e)
        logger.debug("    }")
        result = Result.SKIP

    return TestResult(result, reason)
