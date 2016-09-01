from reconbf.modules import test_horizon
from reconbf.lib.result import Result, TestResult
from reconbf.lib import utils

import pwd
import grp
import unittest
from mock import patch


class ConfigPermissions(unittest.TestCase):
    conf = {'dir': '', 'user': '', 'group': ''}
    pwd_root = pwd.struct_passwd(('root', 'x', 0, 0, 'root', '/root',
                                  '/bin/bash'))
    grp_root = grp.struct_group(('root', 'x', 0, []))

    def test_no_user(self):
        with patch.object(pwd, 'getpwnam', side_effect=KeyError()):
            with patch.object(grp, 'getgrnam', return_value=self.grp_root):
                res = test_horizon.config_permission(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def test_no_group(self):
        with patch.object(pwd, 'getpwnam', return_value=self.pwd_root):
            with patch.object(grp, 'getgrnam', side_effect=KeyError()):
                res = test_horizon.config_permission(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def test_good_perm(self):
        with patch.object(pwd, 'getpwnam', return_value=self.pwd_root):
            with patch.object(grp, 'getgrnam', return_value=self.grp_root):
                with patch.object(utils, 'validate_permissions',
                                  return_value=TestResult(Result.PASS)):
                    res = test_horizon.config_permission(self.conf)
        self.assertEqual(res.result, Result.PASS)

    def test_bad_perm(self):
        with patch.object(pwd, 'getpwnam', return_value=self.pwd_root):
            with patch.object(grp, 'getgrnam', return_value=self.grp_root):
                with patch.object(utils, 'validate_permissions',
                                  return_value=TestResult(Result.FAIL)):
                    res = test_horizon.config_permission(self.conf)
        self.assertEqual(res.result, Result.FAIL)


class _ConfigTest():
    conf = {'dir': ''}

    def test_no_config(self):
        with patch.object(test_horizon, '_read_config',
                          side_effect=EnvironmentError()):
            if hasattr(self.func, 'im_func'):
                res = self.func.im_func(self.conf)
            else:
                res = self.func.__func__(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def _run_with_config(self, cfg):
        with patch.object(test_horizon, '_read_config', return_value=cfg):
            if hasattr(self.func, 'im_func'):
                return self.func.im_func(self.conf)
            else:
                return self.func.__func__(self.conf)

    def test_ok(self):
        res = self._run_with_config({self.option: self.good_val})
        self.assertEqual(res.result, Result.PASS)

    def test_bad(self):
        res = self._run_with_config({self.option: self.bad_val})
        self.assertEqual(res.result, Result.FAIL)


class CsrfCookie(_ConfigTest, unittest.TestCase):
    func = test_horizon.csrf_cookie
    good_val = True
    bad_val = False
    option = 'CSRF_COOKIE_SECURE'


class SessionCookie(_ConfigTest, unittest.TestCase):
    func = test_horizon.session_cookie
    good_val = True
    bad_val = False
    option = 'SESSION_COOKIE_SECURE'


class SessionCookieHttp(_ConfigTest, unittest.TestCase):
    func = test_horizon.session_cookie_http
    good_val = True
    bad_val = False
    option = 'SESSION_COOKIE_HTTPONLY'


class PasswordAutocomplete(_ConfigTest, unittest.TestCase):
    func = test_horizon.password_autocomplete
    good_val = 'off'
    bad_val = 'on'
    option = 'HORIZON_CONFIG[password_autocomplete]'


class PasswordReveal(_ConfigTest, unittest.TestCase):
    func = test_horizon.password_reveal
    good_val = True
    bad_val = False
    option = 'HORIZON_CONFIG[disable_password_reveal]'


class Parser(unittest.TestCase):
    def test_empty(self):
        conf = test_horizon._parse_config("")
        self.assertEqual(conf, {})

    def test_ignore_imports(self):
        conf = test_horizon._parse_config("import blah")
        self.assertEqual(conf, {})

    def test_assign_basic(self):
        conf = test_horizon._parse_config(
            """a=0;b="str";c=(1,2);d=[1,2];e={1:2};f={1,2}""")
        self.assertEqual(conf, {'a': 0, 'b': 'str', 'c': (1, 2), 'd': [1, 2],
                                'e': {1: 2}, 'f': {1, 2}})

    def test_assign_slice(self):
        conf = test_horizon._parse_config("a['b']=1")
        self.assertEqual(conf, {'a[b]': 1})

    def test_ignore_destruct(self):
        # destructuring is hard and unlikely to be needed
        conf = test_horizon._parse_config("a,b=1,2;c=3")
        self.assertEqual(conf, {'c': 3})

    def test_ignore_non_const(self):
        # skip non-constant expressions
        conf = test_horizon._parse_config("a=func();c=3")
        self.assertEqual(conf, {'c': 3})
