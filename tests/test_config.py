from reconbf.lib import config

import io
import unittest


class Config(unittest.TestCase):
    def test_load_empty(self):
        config_file = io.StringIO(u"{}")
        cfg = config.Config(config_file)
        self.assertEqual(cfg.get_configured_tests(), {})

    def test_list_tests(self):
        config_file = io.StringIO(u"""{
            "modules":
            {
                "test_kernel": {
                    "test_pax": null
                }
            }
        }""")
        cfg = config.Config(config_file)
        self.assertEqual(cfg.get_configured_tests(),
                         {"test_kernel": ["test_pax"]})
