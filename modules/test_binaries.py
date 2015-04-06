import json
import os
import platform
import stat
import subprocess
import sys
from pprint import pprint
from collections import defaultdict
from lib import test_utils as utils
from lib import test_class
from lib.test_result import TestResult, Result


def _is_elf(path):
    return ' ELF ' in subprocess.check_output(['file', path])


def _is_setuid(path):
    return (os.path.isfile(path) and
            os.access(path, os.X_OK) and
            os.stat(path).st_mode & stat.S_ISUID == stat.S_ISUID)


def _elf_syms(path):
    return subprocess.check_output(['readelf', '-s', path])


def _elf_dynamic(path):
    return subprocess.check_output(['readelf', '-d', path])


def _elf_prog_headers(path):
    return subprocess.check_output(['readelf', '-W', '-l', path])


def _elf_file_headers(path):
    return subprocess.check_output(['readelf', '-h', path])


def _check_relro(path):
    headers = _elf_prog_headers(path)
    if 'GNU_RELRO' in headers:
        dynamic_section = _elf_dynamic(path)
        if 'BIND_NOW' in dynamic_section:
            return 'full'
        else:
            return 'partial'

    return 'none'


def _check_stack_canary(path):
    symbols = _elf_syms(path)
    if '__stack_chk_fail' in symbols:
        return True

    return False


def _check_nx(path):
    headers = _elf_prog_headers(path)
    for line in headers.split('\n'):
        if 'GNU_STACK' and 'RWE' not in line:
            return True

    return False


def _check_pie(path):
    file_headers = _elf_file_headers(path)
    for line in file_headers.split('\n'):
        if 'Type:' in line:
            if 'EXEC' in line:
                return False
            elif 'DYN' in line and '(DEBUG)' in _elf_dynamic(path):
                return True
            else:
                raise ValueError(path + ' is a DSO so PIE test is invalid')


def _check_runpath(path):
    dyn = _elf_dynamic(path)
    return 'rpath' in dyn or 'runpath' in dyn


def _check_fortify(path):
    logger = utils.get_logger()

    libc = '/lib/libc.so.6'
    if platform.machine() == 'x86_64':
        libc = '/lib64/libc.so.6'

    if not os.path.exists(libc):
        logger.debug('  [*] Unable to determine location of libc')
        return False

    fortified = set([])
    for addr, sym, name in _symbols_in_elf(libc):
        if sym == 'T' and name.endswith('_chk'):
            fortified.add(name)

    symbols = set([name for addr, sym, name in _symbols_in_dynsym(path)])
    return len(symbols.intersection(fortified)) > 0


def _extract_symbols(cmd):
    """
    Helper function to reduce code duplication. Only difference
    in output of commands comes from the way the 'nm' command
    is run.

    :param cmd: The way to invoke 'nm' command.
    :returns: Generated symbols resulting from nm invocation.
    """
    logger = utils.get_logger()
    try:
        null = open(os.devnull, 'w')
        entries = subprocess.check_output(cmd, stderr=null)
        for entry in entries.split('\n'):
            try:
                values = entry.strip().split(' ')
                # handle case:
                #                  U __sprintf_chk@@GLIBC_2.3.4
                if len(values) == 2:
                    sym_addr = None
                    sym_type, sym_name = values
                # otherwise expect:
                # 00000000004004b0 T main
                else:
                    sym_addr, sym_type, sym_name = entry.split(' ')

                yield (sym_addr, sym_type, sym_name.split('@@')[0])
            except ValueError as err:
                logger.debug('[*] Unexpected output {' + entry.strip() + '}')

    except subprocess.CalledProcessError as err:
        logger.debug(err)


def _symbols_in_elf(path):
    """
    Generator to return the symbols within an ELF executable or
    shared library. Output taken from the 'nm' command.

    *NOTE* This will note return any results for stripped binaries.

    :param path: The path of the executable or shared library to extract
                 symbols from.

    :returns: Generator that yields the symbols that are either
              defined in, or referenced by a given ELF file.
    """
    return _extract_symbols(['nm', path])


def _symbols_in_dynsym(path):
    """
    Generator to return all the symbols within an ELF executable dynsym
    section. These results will only include the symbols needed for
    dynamic linking at runtime. This section will exists even when the
    binary is stripped.  Essentially this is output taken from `nm -D`

    :param path: The path of the executable to be examined.

    :returns: Generator the yields the symbols in the .dynsym section
              of the ELF binary.
    """
    return _extract_symbols(['nm', '-D', path])


def _check_policy(context, policy, results):
    log = utils.get_logger()
    fmt = "{} does not meet {} policy. expected: {}, actual: {}"
    violations = 0
    for k in policy.keys():
        if policy[k] != results[k]:
            log.info(fmt.format(context, k, policy[k], results[k]))
            violations += 1

    note = "{} violations detected for {}".format(violations, context)
    return (violations, note)


@test_class.takes_config
@test_class.explanation("""

    Protection: Security hardened binaries

    Purpose: Determines which configured setuid processes
    have been built with various security hardening options.

    Status: Experimental

    Check: RELRO - This prevents exploits that write to the GOT
    in ELF executables. To achieve full RELRO you would need
    to build using the flags: $ gcc foo.c -Wl,-z,relro,-z,now.

    Check: Stack Canary - This mitigation mechanism attempts
    to detect buffer overflows by placing a canary value on
    the stack before other locals. If it cannot be verified it
    is an indication that a buffer overflow has occurred.
    To build a binary with stack protector enable you need to
    use one of the -fstack-protector, -fstack-protector-strong
    or -fstack-protector-all command line options. The indicator
    we are looking for here is the symbol __stack_chk_fail.

    Check: NX - This mitigation technique attempts to mark
    as the binary as non-executable memory. E.g. An attacker
    can't as easily fill a buffer with shellcode and jump
    to the start address. It is common for this to be disabled
    for things like JIT interpreters.

    Check: PIE - Position independent executables ensure that
    the entire address space is randomized, including the base
    executable position in memory. This makes return to libc
    type attacks more difficult to achive. To compile an
    executable as a PIE: $ gcc foo.c -fPIE -pie.

    Check: Fortify Source - This introduces support for
    detecting buffer overflows in various functions that perform
    operations on memory and strings. The indicator for this is
    symbols such as __sprintf_chk rather then __sprintf. To compile
    an executable with fortify source enabled:
        $ gcc foo.c -D_FORTIFY_SOURCE=2 -O2

    Check: Run Path - Baking in a fixed run path to shared libraries
    can leave executables open to various attacks. This detects
    binaries that have either rpath or runpath enabled.
    """)
def test_setuid_files(config):
    if not utils.have_command("readelf") or not utils.have_command("nm"):
        return TestResult(Result.SKIP, notes="readelf needed for this test")

    setup = None
    try:
        setup = json.loads(open(config['config_file']).read())
    except OSError:
        return TestResult(Result.SKIP, notes="Unable to find test config")

    policy = setup['setuid']['policy']
    for path in utils.executables_in_path():
        if (os.path.exists(path) and _is_setuid(path) and _is_elf(path)):
            results = {
                "relro":        _check_relro(path),
                "pie":          _check_pie(path),
                "stack_canary": _check_stack_canary(path),
                "nx":           _check_nx(path),
                "fortify":      _check_fortify(path),
                "runpath":      _check_runpath(path)
            }
            violations, summary = _check_policy(path, policy, results)
            if violations > 0:
                return TestResult(Result.FAIL, notes=summary)

    return TestResult(Result.PASS)
