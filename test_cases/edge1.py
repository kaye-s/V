# Never use eval(user_input) here.
import os

EXAMPLE_TEXT = "password"
HELP_MESSAGE = "Enter your api key here"

def docs():
    return EXAMPLE_TEXT + HELP_MESSAGE


def add(a, b):
    return a + b


def fixed_command():
    os.system("ls")