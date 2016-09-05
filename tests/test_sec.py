from reconbf.modules import test_sec
from reconbf.lib.result import Result
from reconbf.lib import utils

import unittest
from mock import patch


class SysctlValues(unittest.TestCase):
    def test_match(self):
        with patch.object(utils, 'get_sysctl_value', return_value="bar"):
            res = test_sec.test_sysctl_values({"x": ("match", "bar")})
        self.assertEqual(res.result, Result.PASS)

    def test_not_match(self):
        with patch.object(utils, 'get_sysctl_value', return_value="bar"):
            res = test_sec.test_sysctl_values({"x": ("match", "xxx")})
        self.assertEqual(res.result, Result.FAIL)

    def test_one_of(self):
        with patch.object(utils, 'get_sysctl_value', return_value="bar"):
            res = test_sec.test_sysctl_values({"x": ("one_of", ["bar", "x"])})
        self.assertEqual(res.result, Result.PASS)

    def test_not_one_of(self):
        with patch.object(utils, 'get_sysctl_value', return_value="bar"):
            res = test_sec.test_sysctl_values({"x": ("one_of", ["x"])})
        self.assertEqual(res.result, Result.FAIL)

    def test_none_of(self):
        with patch.object(utils, 'get_sysctl_value', return_value="bar"):
            res = test_sec.test_sysctl_values({"x": ("none_of", ["x"])})
        self.assertEqual(res.result, Result.PASS)

    def test_not_none_of(self):
        with patch.object(utils, 'get_sysctl_value', return_value="bar"):
            res = test_sec.test_sysctl_values({"x": ("none_of", ["bar", "x"])})
        self.assertEqual(res.result, Result.FAIL)

    def test_at_least(self):
        with patch.object(utils, 'get_sysctl_value', return_value="10"):
            res = test_sec.test_sysctl_values({"x": ("at_least", "5")})
        self.assertEqual(res.result, Result.PASS)

    def test_not_at_least(self):
        with patch.object(utils, 'get_sysctl_value', return_value="0"):
            res = test_sec.test_sysctl_values({"x": ("at_least", "5")})
        self.assertEqual(res.result, Result.FAIL)

    def test_without_description(self):
        with patch.object(utils, 'get_sysctl_value', return_value="foo"):
            res = test_sec.test_sysctl_values({"x": ("match", "foo")})
        self.assertEqual(res.results[0]['name'], "x")

    def test_with_description(self):
        with patch.object(utils, 'get_sysctl_value', return_value="foo"):
            res = test_sec.test_sysctl_values({"x": ("match", "foo", "bar")})
        self.assertEqual(res.results[0]['name'], "bar")
