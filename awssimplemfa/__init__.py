from . import patcher


def awscli_initialize(cli):
    patcher.patch()

