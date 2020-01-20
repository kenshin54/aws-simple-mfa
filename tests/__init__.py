import unittest
import mock
import os
import binascii


class BaseEnvVar(unittest.TestCase):
    def setUp(self):
        # Automatically patches out os.environ for you
        # and gives you a self.environ attribute that simulates
        # the environment.  Also will automatically restore state
        # for you in tearDown()
        self.environ = {}
        self.environ_patch = mock.patch('os.environ', self.environ)
        self.environ_patch.start()

    def tearDown(self):
        self.environ_patch.stop()
