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
from reconbf.lib import test_class
from reconbf.lib.result import GroupTestResult
from reconbf.lib.result import Result
from reconbf.lib.result import TestResult
from reconbf.lib import utils

import multiprocessing
import os
import pwd
import stat
import subprocess
try:
    import Queue as queue
except ImportError:
    import queue


def _is_elf(path):
    try:
        header = open(path, 'rb').read(4)
        return header == b'\x7fELF'
    except IOError:
        return False


def _is_setuid(path):
    return (os.path.isfile(path) and
            os.access(path, os.X_OK) and
            os.stat(path).st_mode & stat.S_ISUID == stat.S_ISUID)


def _safe_child(to_exec, q, uid, gid):
    try:
        os.setgroups([])
        os.setregid(gid, gid)
        os.setreuid(uid, uid)

        res = subprocess.check_output(to_exec, stderr=open(os.devnull, 'w'))
        q.put(res)
    except Exception as e:
        q.put(e)


def _safe_exec(to_exec, user="nobody"):
    pwentry = pwd.getpwnam(user)
    q = multiprocessing.Queue()
    p = multiprocessing.Process(
        target=_safe_child,
        args=(to_exec, q, pwentry.pw_uid, pwentry.pw_gid))
    p.start()
    try:
        res = q.get(True, 5)
        p.join(1)
    except queue.Empty:
        p.terminate()
        raise Exception("Failed to execute command %s" % to_exec)
    except:
        p.terminate()
        raise

    if isinstance(res, Exception):
        raise res  # forward child exception
    else:
        return res


def _elf_syms(path):
    try:
        return _safe_exec(['readelf', '-s', path])
    except subprocess.CalledProcessError:
        # file not readable
        return None


@utils.idempotent
def _elf_dynamic(path):
    try:
        return _safe_exec(['readelf', '-d', path])
    except subprocess.CalledProcessError:
        # file not readable
        return None


@utils.idempotent
def _elf_prog_headers(path):
    try:
        return _safe_exec(['readelf', '-W', '-l', path])
    except subprocess.CalledProcessError:
        # file not readable
        return None


def _elf_file_headers(path):
    try:
        return _safe_exec(['readelf', '-h', path])
    except subprocess.CalledProcessError:
        # file not readable
        return None


def _check_relro(path):
    """RELRO - This prevents exploits that write to the GOT
    in ELF executables. To achieve full RELRO you would need
    to build using the flags: $ gcc foo.c -Wl,-z,relro,-z,now.
    """
    headers = _elf_prog_headers(path)
    if headers is None:
        return (None, Result.CONF_GUESS)

    if b'GNU_RELRO' in headers:
        dynamic_section = _elf_dynamic(path)
        if b'BIND_NOW' in dynamic_section:
            return ('full', Result.CONF_SURE)
        else:
            return ('partial', Result.CONF_SURE)

    return ('none', Result.CONF_SURE)


def _check_stack_canary(path):
    """Stack Canary - This mitigation mechanism attempts
    to detect buffer overflows by placing a canary value on
    the stack before other locals. If it cannot be verified it
    is an indication that a buffer overflow has occurred.
    To build a binary with stack protector enable you need to
    use one of the -fstack-protector, -fstack-protector-strong
    or -fstack-protector-all command line options. The indicator
    we are looking for here is the symbol __stack_chk_fail.
    """
    symbols = _elf_syms(path)
    if symbols is None:
        return (None, Result.CONF_GUESS)

    if b'__stack_chk_fail' in symbols:
        return (True, Result.CONF_SURE)

    # with just -fstack-protector the application may not contain any functions
    # that the compiler considers worth securing
    return (False, Result.CONF_GUESS)


def _check_nx(path):
    """NX - This mitigation technique attempts to mark
    as the binary as non-executable memory. E.g. An attacker
    can't as easily fill a buffer with shellcode and jump
    to the start address. It is common for this to be disabled
    for things like JIT interpreters.
    """
    headers = _elf_prog_headers(path)
    if headers is None:
        return (None, Result.CONF_GUESS)

    for line in headers.split(b'\n'):
        if b'GNU_STACK' in line and b'RWE' not in line:
            return (True, Result.CONF_SURE)

    return (False, Result.CONF_SURE)


def _check_pie(path):
    """PIE - Position independent executables ensure that
    the entire address space is randomized, including the base
    executable position in memory. This makes return to libc
    type attacks more difficult to achive. To compile an
    executable as a PIE: $ gcc foo.c -fPIE -pie.
    """
    file_headers = _elf_file_headers(path)
    if file_headers is None:
        return (None, Result.CONF_GUESS)

    for line in file_headers.split(b'\n'):
        if b'Type:' in line:
            if b'EXEC' in line:
                return (False, Result.CONF_SURE)
            elif b'DYN' in line and b'(DEBUG)' in _elf_dynamic(path):
                return (True, Result.CONF_SURE)
            else:
                raise ValueError(path + ' is a DSO so PIE test is invalid')


def _check_runpath(path):
    """Run Path - Baking in a fixed run path to shared libraries
    can leave executables open to various attacks. This detects
    binaries that have either rpath or runpath enabled.
    """

    dyn = _elf_dynamic(path)
    if dyn is None:
        return (None, Result.CONF_GUESS)

    return (b'rpath' in dyn or b'runpath' in dyn, Result.CONF_SURE)


def _find_used_libc(path):
    """Find the libc file which would be used on execution of the provided
    binary. This is not trivial to find out from outside and needs to be
    resolved by actual linker.
    """

    try:
        output = _safe_exec(['ldd', path])
    except subprocess.CalledProcessError:
        # likely not a dynamic executable
        return None

    for line in output.splitlines():
        parts = line.split(b'=>')
        if len(parts) < 2:
            continue

        libname = parts[0].strip()
        if not libname.startswith(b'libc.so'):
            continue

        filename = parts[1].strip().split()[0]
        if not os.path.exists(filename):
            # ldd just told us it does exist, something really weird is
            # happening - maybe there's another one?
            continue

        return filename

    # libc not found for some reason
    return None


def _check_fortify(path):
    """Fortify Source - This introduces support for
    detecting buffer overflows in various functions that perform
    operations on memory and strings. The indicator for this is
    symbols such as __sprintf_chk rather then __sprintf. To compile
    an executable with fortify source enabled:
        $ gcc foo.c -D_FORTIFY_SOURCE=2 -O2
    """
    libc = _find_used_libc(path)
    if not libc:
        logger.debug('Unable to determine location of libc')
        return (False, Result.CONF_GUESS)

    fortified = set([])
    for addr, sym, name in _symbols_in_dynsym(libc):
        if sym in (b'T', b'i') and name.endswith(b'_chk'):
            fortified.add(name)
    plain = set(name[2:-4] for name in fortified)

    symbols = set([name for addr, sym, name in _symbols_in_dynsym(path)])
    if len(symbols.intersection(fortified)) > 0:
        return (True, Result.CONF_SURE)

    # if there are no functions to fortify, treat it the same as fortified
    if len(symbols.intersection(plain)) == 0:
        return (True, Result.CONF_SURE)

    # there may be a situation where a function is used on a buffer of unknown
    # size and cannot be fortified - or it may be just not fortified
    return (False, Result.CONF_GUESS)


def _extract_symbols(cmd):
    """Helper function to reduce code duplication. Only difference
    in output of commands comes from the way the 'nm' command
    is run.

    :param cmd: The way to invoke 'nm' command.
    :returns: Generated symbols resulting from nm invocation.
    """
    try:
        entries = _safe_exec(cmd)
        for entry in entries.split(b'\n'):
            try:
                values = entry.strip().split(b' ')
                # handle case:
                #                  U __sprintf_chk@@GLIBC_2.3.4
                if len(values) == 2:
                    sym_addr = None
                    sym_type, sym_name = values
                # otherwise expect:
                # 00000000004004b0 T main
                else:
                    sym_addr, sym_type, sym_name = entry.split(b' ')

                yield (sym_addr, sym_type, sym_name.split(b'@@')[0])
            except ValueError as err:
                logger.debug('Unexpected output [ %s ]', entry.strip())

    except subprocess.CalledProcessError as err:
        logger.debug(err)


@utils.idempotent
def _symbols_in_dynsym(path):
    """Generator to return all the symbols within an ELF executable dynsym
    section. These results will only include the symbols needed for
    dynamic linking at runtime. This section will exists even when the
    binary is stripped.  Essentially this is output taken from `nm -D`

    :param path: The path of the executable to be examined.
    :param _cache: Cache for results. We don't expect binaries to change
        mid-run.

    :returns: List of the symbols in the .dynsym section of the ELF binary.
    """
    return list(_extract_symbols(['nm', '-D', path]))


def _check_policy(context, policy, actual, results):
    fmt = "Expected: {} Actual: {}"
    for k in policy.keys():
        check = "[{:^12s}] {}".format(k, context)
        if actual[k][0] is None:
            results.add_result(check, TestResult(Result.SKIP,
                                                 "cannot access file"))
        elif policy[k] != actual[k][0]:
            exp = str(policy[k]).capitalize()
            act = str(actual[k][0]).capitalize()
            failure = fmt.format(exp, act)
            results.add_result(check, TestResult(Result.FAIL, notes=failure,
                                                 confidence=actual[k][1]))
        else:
            results.add_result(check, TestResult(Result.PASS,
                                                 confidence=actual[k][1]))


def _check_binaries(policy, filelist, predicate):
    if not utils.have_command("readelf") or not utils.have_command("nm"):
        return TestResult(Result.SKIP, notes="readelf needed for this test")

    results = GroupTestResult()
    for path in filelist:
        if predicate(path):
            actual = {
                "relro":        _check_relro(path),
                "pie":          _check_pie(path),
                "stack_canary": _check_stack_canary(path),
                "nx":           _check_nx(path),
                "fortify":      _check_fortify(path),
                "runpath":      _check_runpath(path)
            }
            _check_policy(path, policy, actual, results)

    return results


def _conf_test_setuid_files():
    return {"relro": "full",
            "stack_canary": True,
            "nx": True,
            "pie": True,
            "runpath": False,
            "fortify": True
            }


@test_class.takes_config(_conf_test_setuid_files)
@test_class.explanation("""
    Protection name: Security hardened suid binaries

    Check: Ensures all setuid executables on the system
    path have been built with various security hardening
    options enabled.

    Purpose: Setuid binaries should be built with as many
    hardening options enabled as possible.
    """)
def test_setuid_files(policy):
    if not utils.have_command("readelf") or not utils.have_command("nm"):
        return TestResult(Result.SKIP, notes="readelf needed for this test")

    if not policy:
        return TestResult(Result.SKIP, notes="Unable to find test config")

    predicate = lambda x: os.path.exists(x) and _is_setuid(x) and _is_elf(x)
    return _check_binaries(policy, utils.executables_in_path(), predicate)


def _conf_test_listening_files():
    return {"relro": "full",
            "stack_canary": True,
            "nx": True,
            "pie": True,
            "runpath": False,
            "fortify": True
            }


@test_class.takes_config(_conf_test_listening_files)
@test_class.explanation("""
    Protection name: Security hardened listening binaries

    Check: Ensures all applications running on the system
    have binaries which have been built with various
    security hardening options enabled.

    Purpose: Daemon applications should be built with as many
    hardening options enabled as possible.
    """)
def test_listening_files(policy):
    if not utils.have_command("readelf") or not utils.have_command("nm"):
        return TestResult(Result.SKIP, notes="readelf needed for this test")

    if not policy:
        return TestResult(Result.SKIP, notes="Unable to find test config")

    predicate = lambda x: os.path.exists(x) and _is_elf(x)
    return _check_binaries(policy, utils.listening_executables(), predicate)


def _conf_test_system_critical():
    return {
        "policy": {
            "relro": "full",
            "stack_canary": True,
            "nx": True,
            "pie": True,
            "runpath": False,
            "fortify": True
        },
        "paths": [
            "/usr/sbin/httpd",
            "/usr/sbin/sshd"
        ]
    }


@test_class.takes_config(_conf_test_system_critical)
@test_class.explanation("""
    Protection name: Security hardened binaries

    Check: Ensures configured security critical applications
    have been built with various mitigation technologies
    enabled.

    Purpose: Network facing applications that run as root,
    or allow external access to the system should be built
    as hardened binaries. This check will ensure these
    applications are built using RELRO, PIE, Stack Canary,
    Non-Executable Stack, Fortify Source, and without a
    hard coded Run Path.
    """)
def test_system_critical(setup):
    if not setup:
        return TestResult(Result.SKIP, notes="Unable to find test config")

    policy = setup['policy']
    filelist = setup['paths']
    predicate = lambda x: os.path.exists(x) and _is_elf(x)
    return _check_binaries(policy, filelist, predicate)
