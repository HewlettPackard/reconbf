import ctypes
import errno
import os
import pwd
from multiprocessing import Process, Value

from reconbf.lib import test_class
from reconbf.lib import utils
from reconbf.lib.result import GroupTestResult, Result, TestResult


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

    config = utils.kconfig()
    if not config:
        return TestResult(Result.SKIP, notes="Unable to find kernel config")

    if not utils.kconfig_option('CONFIG_GRKERNSEC', config):
        return TestResult(Result.FAIL,
                          notes="Kernel not compiled with GRSECURITY patches")

    results = GroupTestResult()
    for test, setting in pax_kernel_options.items():
        enabled = utils.kconfig_option(setting, config)
        if enabled and enabled == 'y':
            results.add_result(test, TestResult(Result.PASS))
        else:
            results.add_result(test, TestResult(Result.FAIL))

    return results


def _maps_readable(pid):
    files = [
        '/proc/{}/maps'.format(pid),
        '/proc/{}/smaps'.format(pid),
        '/proc/{}/task/{}/maps'.format(pid, pid),
        '/proc/{}/task/{}/smaps'.format(pid, pid),
    ]

    for filename in files:
        try:
            with open(filename) as f:
                return f.read()
        except IOError as e:
            if e.errno not in [errno.EPERM, errno.EACCES, errno.ENOENT]:
                raise e


def _can_read_from_own(result):
    """Make sure we can read our own /proc/$pid/maps"""
    pid = os.getpid()
    result.value = True if _maps_readable(pid) else False


def _can_read_any_with_same_uid(result):
    """Make sure we can read /proc/$pid maps for any
    process owned by us. In this case we use parent
    process that spawned this process (using multiprocessing).
    """
    parent_pid = os.getppid()
    result.value = True if _maps_readable(parent_pid) else False


def _cant_read_others(result):
    """Make sure that we can't read any other users maps file. To
    do this we need to switch to a less privileged user
    account as rbf.py runs as root.
    """
    # Change to nobody user
    os.setuid(pwd.getpwnam('nobody').pw_uid)

    # Make sure we can't read init process (owned by root)
    result.value = True if _maps_readable(1) else False


def _cant_read_parents_when_priv_dropped(result):
    """Make sure that we can't read our parents maps file
    when privileges are dropped."""

    # Change to nobody user
    os.setuid(pwd.getpwnam('nobody').pw_uid)

    # Make sure can't read parents process (owned by root)
    result.value = True if _maps_readable(os.getppid()) else False


@test_class.explanation("""
    Protection name: /proc/$pid/maps

    Check: Ensures that the correct access controls are in place for
    process memory layouts.

    Purpose:
        * Ensure that a /proc maps aren't world readable
        * Ensure that setuid priv-dropped process can still read
          their own maps files.
    """)
def test_proc_map_access():
    tests = {
        "Can read own /proc/$pid/maps file": {
            "function": _can_read_from_own,
            "expected": True
        },
        "Can read others process /proc/$pid/maps with same UID": {
            "function": _can_read_any_with_same_uid,
            "expected": True
        },
        "Can't read /proc/$pid/maps of other processes": {
            "function": _cant_read_others,
            "expected": False
        },
        "Can't read parents after privileges were dropped": {
            "function": _cant_read_parents_when_priv_dropped,
            "expected": False
        }
    }
    results = GroupTestResult()
    for t in tests:
        fn = tests[t]["function"]
        exp = tests[t]["expected"]
        act = Value(ctypes.c_bool)
        p = Process(target=fn, args=(act,))
        p.start()
        p.join()

        result = Result.PASS if exp == act.value else Result.FAIL
        results.add_result(t, TestResult(result))

    return results


@test_class.explanation("""
    Protection name: ptrace scope

    Check: Test if ptrace scope control is enabled

    Purpose: Kernels compiled with YAMA enabled prevent attackers
    from using compromised processes to attach to other running
    processes and extract sensitive key information from memory.

    For more information see:

        https://www.kernel.org/doc/Documentation/security/Yama.txt
    """)
def test_ptrace_scope():
    ptrace_scope = '/proc/sys/kernel/yama/ptrace_scope'
    kernel_compiled_with_yama = utils.kconfig_option(
        "CONFIG_SECURITY_YAMA")
    if not kernel_compiled_with_yama:
        return TestResult(Result.FAIL,
                          notes="Kernel missing CONFIG_SECURITY_YAMA")
    enabled = int(open(ptrace_scope).read().strip())
    rc = Result.PASS if enabled >= 1 else Result.FAIL
    return TestResult(rc, notes="{} = {}".format(ptrace_scope, enabled))


@test_class.explanation("""
    Protection name: KASLR enabled

    Check: Test if KASLR is active right now

    Purpose: Similar to ASLR, kernel can be relocated to different
    positions. This can be used for mitigating remote kernel exploits.
    This protection is not as good as binaries ASLR, usually
    provides only around 8 bits of randomness, and has known local
    workarounds, however it can still block some of the remote
    vulnerabilities.
    """)
def test_kaslr():
    try:
        with open('/sys/kernel/boot_params/data', 'rb') as params_file:
            params = params_file.read()
    except IOError:
        return TestResult(Result.SKIP, "boot parameters are not available "
                                       "on the /sys filesystem")

    # setup_header at 0x1f1, loadflags 32 bytes in
    loadflags = params[0x1f1 + 32]
    if isinstance(loadflags, str):
        loadflags = ord(loadflags)

    if loadflags & 2:
        return TestResult(Result.PASS, "Kaslr enabled")
    else:
        return TestResult(Result.FAIL, "Kaslr disabled")
