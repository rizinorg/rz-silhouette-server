#!/usr/bin/python3
# SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import sys
import json
import os.path
import re
from clang.cindex import *

hardcoded_fixes_types = {
	'*restrict': '*',
	'*_restrict': '*',
	'*__restrict': '*',
	'*const': '* const',
	'std::size_t': 'size_t',
	'__size_t': 'size_t',
	'__ssize_t': 'ssize_t',
	'_FILE': 'FILE',
	'__FILE': 'FILE',
	'__int': 'int',
	'__uint': 'uint',
	' &': '&',
}

hardcoded_fixes_functions = {
	"tolower": "int tolower(int c);",
	"toupper": "int toupper(int c);",
}

def read_json(path):
	with open(path, 'r') as fp:
		return json.load(fp)

def write_json(path, data):
	with open(path, 'w') as fp:
		json.dump(data, fp, indent=4, sort_keys=True)

def sanitize_type(atype):
	for key in hardcoded_fixes_types:
		atype = atype.replace(key, hardcoded_fixes_types[key])
	return atype


def get_arg_spelling(node, idx):
	atype = sanitize_type(node.type.spelling)

	aname = re.sub(r'^_+', '', node.spelling)
	if aname == '':
		aname = "arg{}".format(idx)

	if node.type.get_pointee().spelling != '':
		# arg is a pointer
		if node.type.get_pointee().get_declaration().spelling == '':
			# is not a known pointer type
			atype = 'void *'

	return ' '.join([atype, aname])

def function_signature(node):
	signature = ""
	if node.spelling in hardcoded_fixes_functions:
		signature = hardcoded_fixes_functions[node.spelling]
	else:
		args = []
		for arg in node.get_arguments():
			decl = get_arg_spelling(arg, len(args))
			args.append(decl)

		signature = "{ret} {name}({args});".format(
			ret=sanitize_type(node.result_type.spelling),
			name=node.spelling,
			args=', '.join(args)
		).replace(' *', '*')

	return node.spelling, node.mangled_name, signature

def parse_c_cpp_to_json(filename, args, data):
	idx = Index.create()
	tu = idx.parse(filename, args=args)
	for node in tu.cursor.walk_preorder():
		if node.kind in [CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD]:
			if len(node.spelling) < 2:
				continue
			name, mangled, sig = function_signature(node)
			data[name] = sig
			if mangled != name and len(mangled) < 2:
				data[mangled] = sig
	return data

def usage():
	help_msg = "{} [output.json] [source dir] [clang options]".format(sys.argv[0])
	for arg in sys.argv:
		if arg in ['-h', '--help']:
			print(help_msg)
			sys.exit(1)

	if len(sys.argv) < 3:
		print(help_msg)
		sys.exit(1)

	if not os.path.isfile(sys.argv[1]):
		print("'{}' does not exists".format(sys.argv[1]))
		sys.exit(1)

	if not os.path.isfile(sys.argv[2]):
		print("'{}' does not exists".format(sys.argv[2]))
		sys.exit(1)

if __name__ == '__main__':
	usage()

	args = []
	for arg in sys.argv[3:]:
		args.append('' + arg)

	data = read_json(sys.argv[1])
	data = parse_c_cpp_to_json(sys.argv[2], args, data)
	write_json(sys.argv[1], data)
	print("read", sys.argv[2])

