#!/usr/bin/env python3
"""A stand-in vault for tests: prints the value for NAME from the JSON file
named by FAKE_VAULT, exit 3 when unknown. Usage: fake_vault.py NAME"""
import json
import os
import sys

store = json.load(open(os.environ["FAKE_VAULT"]))
name = sys.argv[1]
if name not in store:
    print(f"no such secret: {name}", file=sys.stderr)
    sys.exit(3)
print(store[name])
