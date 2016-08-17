from reconbf.modules import test_kernel
from reconbf.lib.result import Result
from reconbf.lib import utils

import unittest
from mock import patch


class PtraceScope(unittest.TestCase):
    def test_no_yama(self):
        with patch.object(utils, 'kconfig_option', return_value=None):
            res = test_kernel.test_ptrace_scope()
        self.assertEqual(res.result, Result.FAIL)

    def test_level_0(self):
        with patch.object(utils, 'kconfig_option', return_value='y'):
            with patch.object(utils, 'get_sysctl_value', return_value='0'):
                res = test_kernel.test_ptrace_scope()
        self.assertEqual(res.result, Result.FAIL)

    def test_level_1(self):
        with patch.object(utils, 'kconfig_option', return_value='y'):
            with patch.object(utils, 'get_sysctl_value', return_value='1'):
                res = test_kernel.test_ptrace_scope()
        self.assertEqual(res.result, Result.PASS)
