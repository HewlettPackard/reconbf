import os
import subprocess

from lib import test_class
from lib.test_result import GroupTestResult, Result, TestResult
from lib import test_utils as utils


def _kernel_version():
    """Return the kernel version information"""
    return subprocess.check_output(['uname', '-r']).strip()


def _kconfig():
    """ Return the contents of the kernel configuration"""
    paths = [
        '/proc/config.gz',
        '/boot/config-{}'.format(_kernel_version()),
        '{}/.config'.format(os.getenv('KCONFIG_BUILD', '/usr/src/linux'))
    ]

    for path in paths:
        if os.path.exists(path):
            try:
                null = open(os.devnull, 'w')
                cmd = ['zcat', '-q', path]
                return subprocess.check_output(cmd, stderr=null)

            except subprocess.CalledProcessError:
                return open(path).read()


def _kconfig_option(option, config=None):
    """Return the value of a kernel configuration option or None
    if it isn't set
    """
    if not config:
        config = _kconfig()

    if not config:
        utils.get_logger().info("[-] Unable to find kernel config!")
        return None

    for line in config.split('\n'):
        if line.startswith('#') or option not in line:
            continue
        opt, val = line.split("=")
        return val


@test_class.explanation("""
    Protection name: Kernel PaX settings

    Check: CONFIG_PAX_KERNEXEC - This is the kernel land
    equivalent of PAGEEXEC and MPROTECT, that is, enabling this
    option will make it harder to inject and execute 'foreign'
    code in kernel memory itself.

    Check: CONFIG_PAX_NOEXEC - Prevents executable memory in
    pages.

    Check: CONFIG_PAX_PAGEXEC - Essentially the PAX_NOEXEC
    implementation using the paging feature of the CPU.

    Check: CONFIG_PAX_MPROTECT - Prevents applications from
    changing the executable status of memory pages that
    were not originally created as executable, marking read-only
    executable pages writable again, creating executable pages
    from anonymous memory, or marking RELRO data pages writable
    again.

    Check: CONFIG_PAX_ASLR - Address space layout randomization that
    includes top of tasks kernel stack, top of tasks userland stack,
    base address for mmap() request, base address of the main

    Check: CONFIG_PAX_RANDKSTACK - The kernel will randomize every
    task's kernel stack on every system call.

    Check: CONFIG_PAX_RANDUSTACK - The kernel will randomize every
    task's userland stack.

    Check: CONFIG_PAX_RANDMMAP - The kernel will use a randomized
    base address for mmap() request that do not specify one themselves.

    Check: CONFIG_PAX_MEMORY_SANITIZE - The kernel will erase memory
    pages and slab objects as soon as they are freed.

    Check: CONFIG_PAX_MEMORY_STACKLEAK - The kernel will erase the
    kernel stack before it returns from a system call. This in turn
    reduces the information that a kernel stack leak bug can reveal.

    Check: CONFIG_PAX_MEMORY_UDEREF - The kernel will be prevented
    from dereferencing userland pointers in context where the
    kernel expects only kernel pointers.

    Check: CONFIG_PAX_REFCOUNT - The kernel will detect and prevent
    overflowing various kinds of object reference counters.

    Check: CONFIG_PAX_USERCOPY - Kernel will enforce the size of
    heap objects when they are copied in either direction between
    the kernel and userland, even if only a part of the heap object
    is copied.

    Note: Without CONFIG_GRKERNSEC=y these checks will fail.
    Therefore the test will not be run fully unless GRKERNSEC
    is detected.
    """)
def test_pax():
    pax_kernel_options = {
        "Non-executable kernel pages":          "CONFIG_PAX_KERNEXEC",
        "Non-executable pages":                 "CONFIG_PAX_NOEXEC",
        "Paging based non-executable pages":    "CONFIG_PAX_PAGEEXEC",
        "Restrict MPROTECT":                    "CONFIG_PAX_MPROTECT",
        "Address space layout randomization":   "CONFIG_PAX_ASLR",
        "Randomize kernel stack":               "CONFIG_PAX_RANDKSTACK",
        "Randomize user stack":                 "CONFIG_PAX_RANDUSTACK",
        "Randomize MMAP stack":                 "CONFIG_PAX_RANDMMAP",
        "Sanitize freed memory":                "CONFIG_PAX_MEMORY_SANITIZE",
        "Sanitize kernel stack":                "CONFIG_PAX_MEMORY_STACKLEAK",
        "Prevent userspace pointer deref":      "CONFIG_PAX_MEMORY_UDEREF",
        "Prevent kboject refcount overflow":    "CONFIG_PAX_REFCOUNT",
        "Bounds check heap object copies":      "CONFIG_PAX_USERCOPY",
    }

    config = _kconfig()
    if not config:
        return TestResult(Result.SKIP, notes="Unable to find kernel config")

    if not _kconfig_option('CONFIG_GRKERNSEC', config):
        return TestResult(Result.FAIL,
                          notes="Kernel not compiled with GRSECURITY patches")

    results = GroupTestResult()
    for test, setting in pax_kernel_options.items():
        enabled = _kconfig_option(setting, config)
        if enabled and enabled == 'y':
            results.add_result(test, TestResult(Result.PASS))
        else:
            results.add_result(test, TestResult(Result.FAIL))

    return results
