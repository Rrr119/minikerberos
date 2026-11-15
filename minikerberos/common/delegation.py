import enum
import base64
import binascii
from typing import List, Dict


class ACE_TYPE(enum.Enum):
	ACCESS_ALLOWED = 0x00
	ACCESS_DENIED = 0x01
	SYSTEM_AUDIT = 0x02
	ACCESS_ALLOWED_OBJECT = 0x05
	ACCESS_DENIED_OBJECT = 0x07


# Access masks relevant for delegation abuse
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000

# userAccountControl flags relevant for delegation
UAC_TRUSTED_FOR_DELEGATION = 0x00080000        # unconstrained delegation
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000  # constrained delegation with protocol transition (S4U2self to any protocol)


class SID:
	"""Windows Security Identifier"""
	def __init__(self):
		self.revision = None
		self.identifier_authority = None
		self.subauthorities = []

	@staticmethod
	def from_bytes(data: bytes, offset: int = 0):
		"""Parses a SID from data starting at offset. Returns (SID, bytes_consumed)"""
		sid = SID()
		sid.revision = data[offset]
		sub_count = data[offset + 1]
		sid.identifier_authority = int.from_bytes(data[offset + 2: offset + 8], 'big')
		pos = offset + 8
		for _ in range(sub_count):
			sid.subauthorities.append(int.from_bytes(data[pos: pos + 4], 'little'))
			pos += 4
		return sid, pos - offset

	def __str__(self):
		res = 'S-%d-%d' % (self.revision, self.identifier_authority)
		for sub in self.subauthorities:
			res += '-%d' % sub
		return res

	def __repr__(self):
		return '<SID %s>' % str(self)

	def __eq__(self, other):
		if isinstance(other, SID):
			return str(self) == str(other)
		if isinstance(other, str):
			return str(self) == other
		return NotImplemented

	def __hash__(self):
		return hash(str(self))


class ACE:
	"""A single Access Control Entry"""
	def __init__(self):
		self.ace_type = None
		self.ace_flags = None
		self.mask = None
		self.sid = None
		self.object_type = None
		self.inherited_object_type = None

	@staticmethod
	def from_bytes(data: bytes, offset: int = 0):
		"""Parses an ACE from data starting at offset. Returns (ACE, bytes_consumed)"""
		ace = ACE()
		ace.ace_type = data[offset]
		ace.ace_flags = data[offset + 1]
		ace_size = int.from_bytes(data[offset + 2: offset + 4], 'little')
		ace.mask = int.from_bytes(data[offset + 4: offset + 8], 'little')
		pos = offset + 8
		if ace.ace_type in (ACE_TYPE.ACCESS_ALLOWED_OBJECT.value, ACE_TYPE.ACCESS_DENIED_OBJECT.value):
			flags = int.from_bytes(data[pos: pos + 4], 'little')
			pos += 4
			if flags & 0x1:
				ace.object_type = data[pos: pos + 16]
				pos += 16
			if flags & 0x2:
				ace.inherited_object_type = data[pos: pos + 16]
				pos += 16
		ace.sid, _ = SID.from_bytes(data, pos)
		return ace, ace_size

	def is_allow(self):
		return self.ace_type in (ACE_TYPE.ACCESS_ALLOWED.value, ACE_TYPE.ACCESS_ALLOWED_OBJECT.value)


class ACL:
	"""Discretionary/System Access Control List"""
	def __init__(self):
		self.revision = None
		self.aces: List[ACE] = []

	@staticmethod
	def from_bytes(data: bytes, offset: int = 0):
		acl = ACL()
		acl.revision = data[offset]
		# acl_size = int.from_bytes(data[offset+2: offset+4], 'little')
		ace_count = int.from_bytes(data[offset + 4: offset + 6], 'little')
		pos = offset + 8
		for _ in range(ace_count):
			ace, consumed = ACE.from_bytes(data, pos)
			acl.aces.append(ace)
			pos += consumed
		return acl


class SecurityDescriptor:
	"""Self-relative Windows security descriptor (eg. nTSecurityDescriptor)"""
	def __init__(self):
		self.revision = None
		self.control = None
		self.owner_sid = None
		self.group_sid = None
		self.sacl = None
		self.dacl = None

	@staticmethod
	def from_bytes(data: bytes):
		sd = SecurityDescriptor()
		sd.revision = data[0]
		sd.control = int.from_bytes(data[2:4], 'little')
		owner_offset = int.from_bytes(data[4:8], 'little')
		group_offset = int.from_bytes(data[8:12], 'little')
		sacl_offset = int.from_bytes(data[12:16], 'little')
		dacl_offset = int.from_bytes(data[16:20], 'little')
		if owner_offset != 0:
			sd.owner_sid, _ = SID.from_bytes(data, owner_offset)
		if group_offset != 0:
			sd.group_sid, _ = SID.from_bytes(data, group_offset)
		if sacl_offset != 0:
			sd.sacl = ACL.from_bytes(data, sacl_offset)
		if dacl_offset != 0:
			sd.dacl = ACL.from_bytes(data, dacl_offset)
		return sd


def sd_bytes_from_any(data):
	"""
	Accepts a security descriptor as raw bytes, hex string or base64 string
	(the latter two being the usual LDAP/ldapsearch/JSON export formats)
	and returns raw bytes.
	"""
	if isinstance(data, bytes):
		return data
	if isinstance(data, str):
		data = data.strip()
		try:
			return bytes.fromhex(data)
		except ValueError:
			pass
		try:
			return base64.b64decode(data, validate=True)
		except (ValueError, binascii.Error):
			pass
		raise ValueError('Security descriptor string is neither hex nor base64')
	raise ValueError('Unsupported security descriptor type: %s' % type(data))


class AllowedToActEntry:
	"""One principal allowed to act on behalf of other identities, with its access mask"""
	def __init__(self, sid: SID, mask: int):
		self.sid = sid
		self.mask = mask

	def __str__(self):
		return '%s (mask: 0x%08x)' % (self.sid, self.mask)

	def __repr__(self):
		return '<AllowedToActEntry %s>' % str(self)


def parse_allowed_to_act(data) -> List[AllowedToActEntry]:
	"""
	Parses the raw value of the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
	(a self-relative security descriptor) and returns the list of principals
	(SIDs) that are allowed to impersonate users against the target, together
	with their access masks.
	"""
	raw = sd_bytes_from_any(data)
	sd = SecurityDescriptor.from_bytes(raw)
	entries = []
	if sd.dacl is None:
		return entries
	for ace in sd.dacl.aces:
		if ace.is_allow():
			entries.append(AllowedToActEntry(ace.sid, ace.mask))
	return entries


class DelegationChain:
	"""One exploitable delegation path"""
	def __init__(self, delegation_type: str, source: str, steps: List[str]):
		self.delegation_type = delegation_type
		self.source = source
		self.steps = steps

	def __str__(self):
		lines = ['[%s] %s' % (self.delegation_type, self.source)]
		for i, step in enumerate(self.steps, 1):
			lines.append('  %d. %s' % (i, step))
		return '\n'.join(lines)


class DelegationInfo:
	"""
	Consolidated delegation settings of one AD object (user or computer),
	as seen via LDAP attributes.
	"""
	def __init__(self):
		self.samaccountname: str = None
		self.domain: str = None
		self.sid: str = None
		self.spns: List[str] = []
		self.useraccountcontrol: int = 0
		self.allowed_to_delegate_to: List[str] = []   # msDS-AllowedToDelegateTo (SPNs)
		self.allowed_to_act: List[AllowedToActEntry] = []  # parsed msDS-AllowedToActOnBehalfOfOtherIdentity

	@property
	def unconstrained_delegation(self) -> bool:
		return bool(self.useraccountcontrol & UAC_TRUSTED_FOR_DELEGATION)

	@property
	def protocol_transition(self) -> bool:
		return bool(self.useraccountcontrol & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)

	@property
	def constrained_delegation(self) -> bool:
		return len(self.allowed_to_delegate_to) > 0

	@property
	def rbcd(self) -> bool:
		return len(self.allowed_to_act) > 0

	@property
	def has_any_delegation(self) -> bool:
		return self.unconstrained_delegation or self.constrained_delegation or self.rbcd

	@staticmethod
	def from_ldap_entry(entry: Dict):
		"""
		Builds a DelegationInfo from a dict of LDAP attributes.
		Keys are matched case-insensitively. The
		msDS-AllowedToActOnBehalfOfOtherIdentity value may be raw bytes,
		a hex string or a base64 string.
		"""
		def get(name, default=None):
			for key, value in entry.items():
				if key.lower() == name.lower():
					return value
			return default

		def as_list(value):
			if value is None:
				return []
			if isinstance(value, (list, tuple)):
				return [str(v) for v in value]
			return [str(value)]

		info = DelegationInfo()
		info.samaccountname = get('sAMAccountName')
		info.domain = get('domain')
		info.sid = get('objectSid')
		info.spns = as_list(get('servicePrincipalName'))
		uac = get('userAccountControl', 0)
		info.useraccountcontrol = int(uac)
		info.allowed_to_delegate_to = as_list(get('msDS-AllowedToDelegateTo'))
		raw_sd = get('msDS-AllowedToActOnBehalfOfOtherIdentity')
		if raw_sd is not None:
			info.allowed_to_act = parse_allowed_to_act(raw_sd)
		return info

	def delegation_types(self) -> List[str]:
		types = []
		if self.unconstrained_delegation:
			types.append('unconstrained')
		if self.constrained_delegation:
			types.append('constrained%s' % (' (protocol transition)' if self.protocol_transition else ''))
		if self.rbcd:
			types.append('resource-based (rbcd)')
		return types

	def exploitation_chains(self) -> List[DelegationChain]:
		"""Builds the list of exploitable delegation chains for this object"""
		chains = []
		name = self.samaccountname or '<unknown>'
		if self.unconstrained_delegation:
			chains.append(DelegationChain(
				'unconstrained',
				name,
				[
					'Coerce or wait for any machine/user to authenticate to %s (eg. PrinterBug, PetitPotam, phishing)' % name,
					"The victim's TGT is stored in this host's LSASS memory (TRUSTED_FOR_DELEGATION)",
					'Dump the TGT from LSASS (eg. pypykatz/mimikatz) and reuse it (pass-the-ticket) against any service',
				]
			))
		if self.constrained_delegation:
			for spn in self.allowed_to_delegate_to:
				steps = []
				if self.protocol_transition:
					steps.append('S4U2self: request a service ticket for ANY user (no password needed) to %s (protocol transition enabled)' % name)
				else:
					steps.append('Obtain a forwardable service ticket from the victim user to %s (eg. via Kerberos-only auth, no protocol transition!)' % name)
				steps.append('S4U2proxy: present that ticket as additional-ticket to get a ticket for %s impersonating the victim' % spn)
				steps.append('The KDC does not validate the service class of the target SPN: %s can be swapped for any service on the same host (eg. cifs, ldap, host)' % (spn.split('/')[0] if '/' in spn else spn))
				chains.append(DelegationChain('constrained', name, steps))
		if self.rbcd:
			for entry in self.allowed_to_act:
				chains.append(DelegationChain(
					'resource-based',
					name,
					[
						'You must control (know credentials of) the principal with SID %s' % entry.sid,
						'S4U2self: using the controlled account, request a service ticket impersonating ANY user (eg. Administrator) to the controlled account itself',
						'S4U2proxy: present that ticket as additional-ticket to get a ticket impersonating the victim for any SPN on %s' % name,
						'Tooling: minikerberos-getS4U2proxy <kerberos URL of controlled account> <target SPN, eg. cifs/%s> <victim user UPN>' % (name.lower().rstrip('$') if name else '<host>'),
					]
				))
		return chains


def delegation_report(infos: List[DelegationInfo]) -> str:
	"""Renders a printable report of all delegation settings and exploitation chains"""
	lines = []
	lines.append('%-30s | %-40s | %s' % ('Account', 'Delegation type(s)', 'Targets/Allowed principals'))
	lines.append('-' * 110)
	delegated = [info for info in infos if info.has_any_delegation]
	if len(delegated) == 0:
		lines.append('No accounts with delegation settings found.')
		return '\n'.join(lines)
	for info in delegated:
		targets = []
		targets.extend(info.allowed_to_delegate_to)
		targets.extend([str(e.sid) for e in info.allowed_to_act])
		lines.append('%-30s | %-40s | %s' % (
			info.samaccountname,
			', '.join(info.delegation_types()),
			', '.join(targets) if targets else '-',
		))
	lines.append('')
	lines.append('=== Exploitation chains ===')
	for info in delegated:
		for chain in info.exploitation_chains():
			lines.append('')
			lines.append(str(chain))
	return '\n'.join(lines)
