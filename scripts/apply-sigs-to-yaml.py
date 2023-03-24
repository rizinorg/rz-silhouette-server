#!/usr/bin/python3
# SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import json
import yaml
import glob
import sys
import os
import re

def read_json(path):
	with open(path, 'r') as fp:
		return json.load(fp)

def read_yaml(path):
	with open(path, 'r') as fp:
		return yaml.load(fp, Loader=yaml.SafeLoader)

def write_yaml(path, data):
	print("write", path)
	with open(path, 'w') as fp:
		yaml.dump(data, fp)

def usage():
	help_msg = "{} [symbols.json] [search dir]".format(sys.argv[0])
	for arg in sys.argv:
		if arg in ['-h', '--help']:
			print(help_msg)
			sys.exit(1)

	if len(sys.argv) != 3:
		print(help_msg)
		sys.exit(1)

	if not os.path.isfile(sys.argv[1]):
		print("'{}' is not a file or does not exists".format(sys.argv[1]))
		sys.exit(1)

	if not os.path.exists(sys.argv[2]):
		print("'{}' does not exists".format(sys.argv[2]))
		sys.exit(1)

def search_and_replace(filepath, symbols, keys):
	data = read_yaml(filepath)
	name = data["name"]
	if name.startswith("sym."):
		name = name.replace("sym.", "", 1)
	name = re.sub(r'[^A-Za-z\d]', '_', name)
	for key in keys:
		if key[0] != name:
			continue
		signature = symbols[key[1]]
		print("found '{}' (matched: '{}') '{}' -> '{}'".format(key[1], data["name"], data["signature"], signature))
		data["signature"] = signature
		write_yaml(filepath, data)
		return

def search_yamls_and_apply(symbols, keys, root, ext):
	files = glob.glob(root + "/**/" + ext, recursive=True)
	for filepath in files:
		search_and_replace(filepath, symbols, keys)

if __name__ == '__main__':
	usage()

	symbols = read_json(sys.argv[1])
	keys = [[re.sub(r'[^A-Za-z\d]', '_', x), x] for x in symbols]

	if os.path.isfile(sys.argv[2]):
		search_and_replace(sys.argv[2], symbols, keys)
	else:
		root = os.path.abspath(sys.argv[2])
		search_yamls_and_apply(symbols, keys, root, "*.yaml")
		search_yamls_and_apply(symbols, keys, root, "*.yml")
