from reconbf import __main__

import io
import json
import unittest


class ConfigGeneration(unittest.TestCase):
    def test_default(self):
        output = io.StringIO()
        __main__._write_generated_config(output, "default")
        self.assertTrue(len(output.getvalue()) > 0)

    def test_inline(self):
        output = io.StringIO()
        __main__._write_generated_config(output, "inline")
        self.assertTrue(len(output.getvalue()) > 0)


class DefaultConfig(unittest.TestCase):
    def test_all_entries(self):
        """Are all tests contained in the default config"""
        with open("config/rbf.cfg", "r") as f:
            default_config = json.load(f)
        generated = __main__._generate_config('default')

        self.assertEqual(default_config['modules'], generated['modules'])
