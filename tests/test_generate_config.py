from reconbf import __main__

import io
import unittest


class ConfigGeneration(unittest.TestCase):
    def test_default(self):
        output = io.StringIO()
        __main__._generate_config(output, "default")
        self.assertTrue(len(output.getvalue()) > 0)

    def test_inline(self):
        output = io.StringIO()
        __main__._generate_config(output, "inline")
        self.assertTrue(len(output.getvalue()) > 0)
