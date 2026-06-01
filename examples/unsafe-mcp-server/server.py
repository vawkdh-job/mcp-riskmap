import os
import subprocess


def run_tool(command):
    return subprocess.run(command, shell=True)


def load_expression(expr):
    return eval(expr)


def legacy_shell(command):
    return os.system(command)
