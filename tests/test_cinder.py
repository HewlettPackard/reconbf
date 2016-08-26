from reconbf.modules import test_cinder
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
                res = test_cinder.config_permission(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def test_no_group(self):
        with patch.object(pwd, 'getpwnam', return_value=self.pwd_root):
            with patch.object(grp, 'getgrnam', side_effect=KeyError()):
                res = test_cinder.config_permission(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def test_good_perm(self):
        with patch.object(pwd, 'getpwnam', return_value=self.pwd_root):
            with patch.object(grp, 'getgrnam', return_value=self.grp_root):
                with patch.object(utils, 'validate_permissions',
                                  return_value=TestResult(Result.PASS)):
                    res = test_cinder.config_permission(self.conf)
        self.assertEqual(res.result, Result.PASS)

    def test_bad_perm(self):
        with patch.object(pwd, 'getpwnam', return_value=self.pwd_root):
            with patch.object(grp, 'getgrnam', return_value=self.grp_root):
                with patch.object(utils, 'validate_permissions',
                                  return_value=TestResult(Result.FAIL)):
                    res = test_cinder.config_permission(self.conf)
        self.assertEqual(res.result, Result.FAIL)


class CinderAuth(unittest.TestCase):
    conf = {'dir': ''}

    def test_no_config(self):
        with patch.object(utils, 'parse_openstack_ini',
                          side_effect=EnvironmentError()):
            res = test_cinder.cinder_auth(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def _run_with_config(self, os_ini):
        with patch.object(utils, 'parse_openstack_ini', return_value=os_ini):
            return test_cinder.cinder_auth(self.conf)

    def test_keystone(self):
        res = self._run_with_config({'DEFAULT': {'auth_strategy': 'keystone'}})
        self.assertEqual(res.result, Result.PASS)

    def test_other(self):
        res = self._run_with_config({'DEFAULT': {'auth_strategy': 'other'}})
        self.assertEqual(res.result, Result.FAIL)


class KeystoneSecure(unittest.TestCase):
    conf = {'dir': ''}

    def test_no_config(self):
        with patch.object(utils, 'parse_openstack_ini',
                          side_effect=EnvironmentError()):
            res = test_cinder.keystone_secure(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def _run_with_config(self, os_ini):
        with patch.object(utils, 'parse_openstack_ini', return_value=os_ini):
            res = test_cinder.keystone_secure(self.conf)
        return res

    def test_bad_proto(self):
        res = self._run_with_config({'keystone_authtoken': {
            'auth_protocol': 'http',
            'identity_uri': 'https://abc'}})
        self.assertEqual(res.result, Result.FAIL)

    def test_bad_uri(self):
        res = self._run_with_config({'keystone_authtoken': {
            'auth_protocol': 'https',
            'identity_uri': 'http://abc'}})
        self.assertEqual(res.result, Result.FAIL)

    def test_ok(self):
        res = self._run_with_config({'keystone_authtoken': {
            'auth_protocol': 'https',
            'identity_uri': 'https://abc'}})
        self.assertEqual(res.result, Result.PASS)


class NovaSecure(unittest.TestCase):
    conf = {'dir': ''}

    def test_no_config(self):
        with patch.object(utils, 'parse_openstack_ini',
                          side_effect=EnvironmentError()):
            res = test_cinder.nova_secure(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def _run_with_config(self, os_ini):
        with patch.object(utils, 'parse_openstack_ini', return_value=os_ini):
            res = test_cinder.nova_secure(self.conf)
        return res

    def test_bad(self):
        res = self._run_with_config({'DEFAULT': {
            'nova_api_insecure': 'true'}})
        self.assertEqual(res.result, Result.FAIL)

    def test_ok(self):
        res = self._run_with_config({'DEFAULT': {
            'nova_api_insecure': 'false'}})
        self.assertEqual(res.result, Result.PASS)


class GlanceSecure(unittest.TestCase):
    conf = {'dir': ''}

    def test_no_config(self):
        with patch.object(utils, 'parse_openstack_ini',
                          side_effect=EnvironmentError()):
            res = test_cinder.glance_secure(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def _run_with_config(self, os_ini):
        with patch.object(utils, 'parse_openstack_ini', return_value=os_ini):
            res = test_cinder.glance_secure(self.conf)
        return res

    def test_bad(self):
        res = self._run_with_config({'DEFAULT': {
            'glance_api_insecure': 'true'}})
        self.assertEqual(res.result, Result.FAIL)

    def test_ok(self):
        res = self._run_with_config({'DEFAULT': {
            'glance_api_insecure': 'false'}})
        self.assertEqual(res.result, Result.PASS)


class NasSecurity(unittest.TestCase):
    conf = {'dir': ''}

    def test_no_config(self):
        with patch.object(utils, 'parse_openstack_ini',
                          side_effect=EnvironmentError()):
            res = test_cinder.nas_security(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def _run_with_config(self, os_ini):
        with patch.object(utils, 'parse_openstack_ini', return_value=os_ini):
            res = test_cinder.nas_security(self.conf)
        return res

    def test_bad_ops(self):
        res = self._run_with_config({'DEFAULT': {
            'nas_secure_file_operations': 'false',
            'nas_secure_file_permissions': 'auto'}})
        self.assertEqual(res.result, Result.FAIL)

    def test_bad_perm(self):
        res = self._run_with_config({'DEFAULT': {
            'nas_secure_file_operations': 'auto',
            'nas_secure_file_permissions': 'false'}})
        self.assertEqual(res.result, Result.FAIL)

    def test_ok(self):
        res = self._run_with_config({'DEFAULT': {
            'nas_secure_file_operations': 'auto',
            'nas_secure_file_permissions': 'auto'}})
        self.assertEqual(res.result, Result.PASS)

    def test_ok_default(self):
        res = self._run_with_config({'DEFAULT': {}})
        self.assertEqual(res.result, Result.PASS)


class BodySize(unittest.TestCase):
    conf = {'dir': ''}

    def test_no_config(self):
        with patch.object(utils, 'parse_openstack_ini',
                          side_effect=EnvironmentError()):
            res = test_cinder.body_size(self.conf)
        self.assertEqual(res.result, Result.SKIP)

    def _run_with_config(self, os_ini):
        with patch.object(utils, 'parse_openstack_ini', return_value=os_ini):
            res = test_cinder.body_size(self.conf)
        return res

    def test_bad_def(self):
        res = self._run_with_config({
            'DEFAULT': {'osapi_max_request_body_size': '114688'},
            'oslo_middleware': {'max_request_body_size': '999999'}})
        self.assertEqual(res.result, Result.FAIL)

    def test_bad_middle(self):
        res = self._run_with_config({
            'DEFAULT': {'osapi_max_request_body_size': '999999'},
            'oslo_middleware': {'max_request_body_size': '114688'}})
        self.assertEqual(res.result, Result.FAIL)

    def test_ok(self):
        res = self._run_with_config({
            'DEFAULT': {'osapi_max_request_body_size': '114688'},
            'oslo_middleware': {'max_request_body_size': '114688'}})
        self.assertEqual(res.result, Result.PASS)

    def test_ok_default(self):
        res = self._run_with_config({})
        self.assertEqual(res.result, Result.PASS)
