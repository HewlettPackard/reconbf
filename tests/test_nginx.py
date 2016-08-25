from reconbf.modules import test_nginx
from reconbf.lib.result import Result

import os
import unittest
from mock import patch


class SslProtos(unittest.TestCase):
    def test_no_config(self):
        with patch.object(os.path, 'exists', return_value=False):
            res = test_nginx.ssl_protos(["ABC"])
        self.assertEqual(res.result, Result.SKIP)


class SslCiphers(unittest.TestCase):
    def test_no_config(self):
        with patch.object(os.path, 'exists', return_value=False):
            res = test_nginx.ssl_ciphers(["ABC"])
        self.assertEqual(res.result, Result.SKIP)


class SslCert(unittest.TestCase):
    def test_no_config(self):
        with patch.object(os.path, 'exists', return_value=False):
            res = test_nginx.ssl_cert()
        self.assertEqual(res.result, Result.SKIP)


class VersionAdvertise(unittest.TestCase):
    def test_no_config(self):
        with patch.object(os.path, 'exists', return_value=False):
            res = test_nginx.version_advertise()
        self.assertEqual(res.result, Result.SKIP)
