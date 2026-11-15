import base64
import json
import struct
import tempfile

from minikerberos.common.delegation import (
	SID, SecurityDescriptor, parse_allowed_to_act, sd_bytes_from_any,
	DelegationInfo, delegation_report,
	UAC_TRUSTED_FOR_DELEGATION, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION,
	ADS_RIGHT_DS_CONTROL_ACCESS, GENERIC_ALL,
)


def build_sid(*subauthorities, revision=1, id_auth=5):
	res = struct.pack('<BB', revision, len(subauthorities))
	res += id_auth.to_bytes(6, 'big')
	for sub in subauthorities:
		res += struct.pack('<I', sub)
	return res


def build_ace(sid_bytes, mask, ace_type=0x00, ace_flags=0x00):
	body = struct.pack('<I', mask) + sid_bytes
	return struct.pack('<BBH', ace_type, ace_flags, 4 + len(body)) + body


def build_object_ace(sid_bytes, mask, object_type=b'\x01' * 16, ace_type=0x05):
	body = struct.pack('<II', mask, 0x1) + object_type + sid_bytes
	return struct.pack('<BBH', ace_type, 0x00, 4 + len(body)) + body


def build_sd(aces, control=0x8004):
	dacl_body = b''.join(aces)
	dacl = struct.pack('<BBHHH', 2, 0, 8 + len(dacl_body), len(aces), 0) + dacl_body
	header = struct.pack('<BBHIIII', 1, 0, control, 0, 0, 0, 20)
	return header + dacl


SID_ATTACKER = build_sid(21, 1000, 1000, 1000, 1112)
SID_ATTACKER_STR = 'S-1-5-21-1000-1000-1000-1112'
SID_SYSTEM = build_sid(18, id_auth=5)
SID_SYSTEM_STR = 'S-1-5-18'


def test_sid_parse():
	sid, consumed = SID.from_bytes(SID_ATTACKER)
	assert str(sid) == SID_ATTACKER_STR
	assert consumed == len(SID_ATTACKER)
	sid, _ = SID.from_bytes(SID_SYSTEM)
	assert str(sid) == SID_SYSTEM_STR


def test_parse_allowed_to_act_bytes():
	sd = build_sd([
		build_ace(SID_ATTACKER, ADS_RIGHT_DS_CONTROL_ACCESS),
		build_ace(SID_SYSTEM, GENERIC_ALL),
	])
	entries = parse_allowed_to_act(sd)
	assert len(entries) == 2
	assert str(entries[0].sid) == SID_ATTACKER_STR
	assert entries[0].mask == ADS_RIGHT_DS_CONTROL_ACCESS
	assert str(entries[1].sid) == SID_SYSTEM_STR


def test_parse_allowed_to_act_hex_base64():
	sd = build_sd([build_ace(SID_ATTACKER, ADS_RIGHT_DS_CONTROL_ACCESS)])
	entries_hex = parse_allowed_to_act(sd.hex())
	entries_b64 = parse_allowed_to_act(base64.b64encode(sd).decode())
	assert str(entries_hex[0].sid) == SID_ATTACKER_STR
	assert str(entries_b64[0].sid) == SID_ATTACKER_STR


def test_parse_allowed_to_act_object_ace():
	sd = build_sd([build_object_ace(SID_ATTACKER, ADS_RIGHT_DS_CONTROL_ACCESS)])
	entries = parse_allowed_to_act(sd)
	assert len(entries) == 1
	assert str(entries[0].sid) == SID_ATTACKER_STR


def test_parse_allowed_to_act_skips_denied():
	sd = build_sd([
		build_ace(SID_SYSTEM, GENERIC_ALL, ace_type=0x01),  # ACCESS_DENIED
		build_ace(SID_ATTACKER, ADS_RIGHT_DS_CONTROL_ACCESS),
	])
	entries = parse_allowed_to_act(sd)
	assert len(entries) == 1
	assert str(entries[0].sid) == SID_ATTACKER_STR


def test_parse_allowed_to_act_no_dacl():
	sd = struct.pack('<BBHIIII', 1, 0, 0x8004, 0, 0, 0, 0)
	assert parse_allowed_to_act(sd) == []


def test_security_descriptor_owner():
	owner = SID_ATTACKER
	dacl_offset = 20 + len(owner)
	dacl = struct.pack('<BBHHH', 2, 0, 8, 0, 0)
	sd_raw = struct.pack('<BBHIIII', 1, 0, 0x8004, 20, 0, 0, dacl_offset) + owner + dacl
	sd = SecurityDescriptor.from_bytes(sd_raw)
	assert str(sd.owner_sid) == SID_ATTACKER_STR
	assert sd.dacl is not None
	assert len(sd.dacl.aces) == 0


def test_sd_bytes_from_any_invalid():
	try:
		sd_bytes_from_any('!!!not-valid!!!')
		raise AssertionError('should have raised')
	except ValueError:
		pass


def test_delegation_info_uac_flags():
	info = DelegationInfo()
	info.useraccountcontrol = UAC_TRUSTED_FOR_DELEGATION
	assert info.unconstrained_delegation is True
	assert info.protocol_transition is False
	info.useraccountcontrol = UAC_TRUSTED_TO_AUTH_FOR_DELEGATION | 0x200
	assert info.unconstrained_delegation is False
	assert info.protocol_transition is True


def test_delegation_info_from_ldap_entry():
	sd = build_sd([build_ace(SID_ATTACKER, ADS_RIGHT_DS_CONTROL_ACCESS)])
	entry = {
		'sAMAccountName': 'WEBSRV$',
		'userAccountControl': '4096',
		'servicePrincipalName': ['http/websrv.test.corp', 'host/websrv.test.corp'],
		'msDS-AllowedToActOnBehalfOfOtherIdentity': base64.b64encode(sd).decode(),
	}
	info = DelegationInfo.from_ldap_entry(entry)
	assert info.samaccountname == 'WEBSRV$'
	assert info.rbcd is True
	assert info.constrained_delegation is False
	assert str(info.allowed_to_act[0].sid) == SID_ATTACKER_STR
	chains = info.exploitation_chains()
	assert len(chains) == 1
	assert chains[0].delegation_type == 'resource-based'
	chain_text = str(chains[0])
	assert 'S4U2self' in chain_text
	assert 'S4U2proxy' in chain_text
	assert SID_ATTACKER_STR in chain_text


def test_delegation_info_constrained_chains():
	entry = {
		'sAMAccountName': 'SQLSVC',
		'userAccountControl': str(UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
		'msDS-AllowedToDelegateTo': ['mssqlsvc/db.test.corp:1433'],
	}
	info = DelegationInfo.from_ldap_entry(entry)
	assert info.constrained_delegation is True
	assert info.protocol_transition is True
	chains = info.exploitation_chains()
	assert len(chains) == 1
	assert chains[0].delegation_type == 'constrained'
	assert 'S4U2self' in str(chains[0])
	assert 'mssqlsvc/db.test.corp:1433' in str(chains[0])


def test_delegation_info_unconstrained_chains():
	entry = {
		'sAMAccountName': 'OLDSRV$',
		'userAccountControl': str(UAC_TRUSTED_FOR_DELEGATION | 0x1000),
	}
	info = DelegationInfo.from_ldap_entry(entry)
	assert info.unconstrained_delegation is True
	chains = info.exploitation_chains()
	assert len(chains) == 1
	assert chains[0].delegation_type == 'unconstrained'


def test_delegation_report():
	sd = build_sd([build_ace(SID_ATTACKER, ADS_RIGHT_DS_CONTROL_ACCESS)])
	infos = [
		DelegationInfo.from_ldap_entry({
			'sAMAccountName': 'WEBSRV$',
			'userAccountControl': '4096',
			'msDS-AllowedToActOnBehalfOfOtherIdentity': sd.hex(),
		}),
		DelegationInfo.from_ldap_entry({
			'sAMAccountName': 'PLAINUSER',
			'userAccountControl': '512',
		}),
	]
	report = delegation_report(infos)
	assert 'WEBSRV$' in report
	assert 'PLAINUSER' not in report
	assert 'resource-based' in report
	assert 'Exploitation chains' in report


def test_finddelegation_example():
	from minikerberos.examples.finddelegation import finddelegation
	sd = build_sd([build_ace(SID_ATTACKER, ADS_RIGHT_DS_CONTROL_ACCESS)])
	entries = [
		{
			'sAMAccountName': 'WEBSRV$',
			'userAccountControl': 4096,
			'msDS-AllowedToActOnBehalfOfOtherIdentity': base64.b64encode(sd).decode(),
		},
		{
			'sAMAccountName': 'SQLSVC',
			'userAccountControl': str(UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
			'msDS-AllowedToDelegateTo': 'mssqlsvc/db.test.corp',
		},
	]
	with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
		json.dump(entries, f)
		fname = f.name
	infos = finddelegation(fname)
	assert len(infos) == 2
	assert infos[0].rbcd is True
	assert infos[1].constrained_delegation is True


def test_finddelegation_jsonlines():
	from minikerberos.examples.finddelegation import finddelegation
	sd = build_sd([build_ace(SID_ATTACKER, ADS_RIGHT_DS_CONTROL_ACCESS)])
	lines = [
		json.dumps({'sAMAccountName': 'WEBSRV$', 'msDS-AllowedToActOnBehalfOfOtherIdentity': sd.hex()}),
		json.dumps({'sAMAccountName': 'NOPE', 'userAccountControl': 512}),
	]
	with tempfile.NamedTemporaryFile('w', suffix='.jsonl', delete=False) as f:
		f.write('\n'.join(lines))
		fname = f.name
	infos = finddelegation(fname)
	assert len(infos) == 2
	assert infos[0].rbcd is True
	assert infos[1].has_any_delegation is False


def test_parse_sd_example():
	from minikerberos.examples.finddelegation import parse_sd
	sd = build_sd([build_ace(SID_ATTACKER, ADS_RIGHT_DS_CONTROL_ACCESS)])
	with tempfile.NamedTemporaryFile('wb', delete=False) as f:
		f.write(sd)
		fname = f.name
	entries = parse_sd(fname)
	assert len(entries) == 1
	assert str(entries[0].sid) == SID_ATTACKER_STR
