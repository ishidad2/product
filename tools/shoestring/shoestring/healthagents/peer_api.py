from symbollightapi.connector.SymbolPeerConnector import SymbolPeerConnector
from symbollightapi.model.Exceptions import NodeException
from zenlog import log

NAME = 'peer API'


def should_run(_):
	return True


async def validate(context):
	(host, port) = context.peer_endpoint
	try:
		connector = SymbolPeerConnector(host, port, context.directories.certificates)
		chain_statistics = await connector.chain_statistics()
		log.info(f'peer API accessible, height = {chain_statistics.height}')
	except NodeException:
		log.error(f'cannot access peer API at {host} on port {port}')
