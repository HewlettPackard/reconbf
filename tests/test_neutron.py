from reconbf.modules import test_neutron
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
                res = test_neutron.config_permission(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def test_no_group(self):
        with patch.object(pwd, 'getpwnam', return_value=self.pwd_root):
            with patch.object(grp, 'getgrnam', side_effect=KeyError()):
                res = test_neutron.config_permission(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def test_good_perm(self):
        with patch.object(pwd, 'getpwnam', return_value=self.pwd_root):
            with patch.object(grp, 'getgrnam', return_value=self.grp_root):
                with patch.object(utils, 'validate_permissions',
                                  return_value=TestResult(Result.PASS)):
                    res = test_neutron.config_permission(self.conf)
        self.assertEqual(res.result, Result.PASS)

    def test_bad_perm(self):
        with patch.object(pwd, 'getpwnam', return_value=self.pwd_root):
            with patch.object(grp, 'getgrnam', return_value=self.grp_root):
                with patch.object(utils, 'validate_permissions',
                                  return_value=TestResult(Result.FAIL)):
                    res = test_neutron.config_permission(self.conf)
        self.assertEqual(res.result, Result.FAIL)


class _ConfigTest():
    conf = {'dir': ''}

    def test_no_config(self):
        with patch.object(utils, 'parse_openstack_ini',
                          side_effect=EnvironmentError()):
            if hasattr(self.func, 'im_func'):
                res = self.func.im_func(self.conf)
            else:
                res = self.func.__func__(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def _run_with_config(self, cfg):
        with patch.object(utils, 'parse_openstack_ini', return_value=cfg):
            if hasattr(self.func, 'im_func'):
                return self.func.im_func(self.conf)
            else:
                return self.func.__func__(self.conf)

    def test_ok(self):
        res = self._run_with_config(self.good_val)
        self.assertEqual(res.result, Result.PASS)

    def test_bad(self):
        res = self._run_with_config(self.bad_val)
        self.assertEqual(res.result, Result.FAIL)


class Auth(_ConfigTest, unittest.TestCase):
    func = test_neutron.auth
    good_val = {'DEFAULT': {'auth_strategy': 'keystone'}}
    bad_val = {'DEFAULT': {'auth_strategy': 'noauth'}}


class KeystoneSecure(_ConfigTest, unittest.TestCase):
    func = test_neutron.keystone_secure
    good_val = {'keystone_authtoken': {
        'auth_protocol': 'https',
        'identity_uri': 'https://example.com'}}
    bad_val = {'keystone_authtoken': {
        'auth_protocol': 'http',
        'identity_uri': 'https://example.com'}}
    bad_val2 = {'keystone_authtoken': {
        'auth_protocol': 'https',
        'identity_uri': 'http://example.com'}}

    def test_bad_2(self):
        res = self._run_with_config(self.bad_val2)
        self.assertEqual(res.result, Result.FAIL)


class UseSsl(_ConfigTest, unittest.TestCase):
    func = test_neutron.use_ssl
    good_val = {'DEFAULT': {'use_ssl': 'true'}}
    bad_val = {'DEFAULT': {'use_ssl': 'false'}}
