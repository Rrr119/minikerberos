import logging
import json

from minikerberos import logger
from minikerberos.common.delegation import DelegationInfo, delegation_report, parse_allowed_to_act


def load_entries(inputfile):
	"""
	Loads LDAP entries from a JSON file. Supported formats:
	- a JSON list of attribute dicts
	- JSON Lines (one attribute dict per line)
	Attribute names are matched case-insensitively. The
	msDS-AllowedToActOnBehalfOfOtherIdentity value must be hex or base64.
	"""
	with open(inputfile, 'r') as f:
		data = f.read()
	try:
		parsed = json.loads(data)
		if isinstance(parsed, dict):
			parsed = [parsed]
		return parsed
	except json.JSONDecodeError:
		entries = []
		for line in data.splitlines():
			line = line.strip()
			if line == '':
				continue
			entries.append(json.loads(line))
		return entries


def finddelegation(inputfile):
	"""Parses LDAP entries and prints delegation settings + exploitation chains"""
	entries = load_entries(inputfile)
	infos = []
	for entry in entries:
		try:
			infos.append(DelegationInfo.from_ldap_entry(entry))
		except Exception as e:
			logger.warning('Failed to parse entry %s Reason: %s' % (entry.get('sAMAccountName', '?'), e))
	report = delegation_report(infos)
	print(report)
	return infos


def parse_sd(sdfile):
	"""Parses a single raw msDS-AllowedToActOnBehalfOfOtherIdentity blob (binary, hex or base64)"""
	with open(sdfile, 'rb') as f:
		raw = f.read()
	try:
		entries = parse_allowed_to_act(raw)
	except ValueError:
		entries = parse_allowed_to_act(raw.decode())
	if len(entries) == 0:
		print('No principals are allowed to act on behalf of other identities.')
		return entries
	print('Principals allowed to act on behalf of other identities (RBCD):')
	for entry in entries:
		print('  %s' % entry)
	return entries


def main():
	import argparse

	parser = argparse.ArgumentParser(description='Enumerates Kerberos delegation settings (unconstrained, constrained, resource-based) from an LDAP JSON dump and prints exploitation chains')
	parser.add_argument('input', nargs='?', help='JSON or JSONL file with LDAP entries. Attributes used: sAMAccountName, userAccountControl, servicePrincipalName, msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity (hex or base64)')
	parser.add_argument('--sd', help='Parse a single raw msDS-AllowedToActOnBehalfOfOtherIdentity blob from file (binary, hex or base64) and print the allowed SIDs')
	parser.add_argument('-v', '--verbose', action='count', default=0)

	args = parser.parse_args()
	if args.verbose == 0:
		logger.setLevel(logging.WARNING)
	elif args.verbose == 1:
		logger.setLevel(logging.INFO)
	else:
		logger.setLevel(1)

	if args.sd is not None:
		parse_sd(args.sd)
		return
	if args.input is None:
		parser.error('either input or --sd must be supplied')
	finddelegation(args.input)


if __name__ == '__main__':
	main()
