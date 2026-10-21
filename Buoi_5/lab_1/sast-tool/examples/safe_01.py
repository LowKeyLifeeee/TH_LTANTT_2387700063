"""Example after removing hardcoded secrets, pickle and eval."""

import ast
import os


def load_password():
    return os.environ.get("LAB_PASSWORD")


def parse_data(data):
    # Accept Python literals, never execute arbitrary expressions.
    return ast.literal_eval(data)


def safe_func():
    print("Hello world!")
