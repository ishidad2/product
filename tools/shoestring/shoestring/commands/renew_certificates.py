import os
from pathlib import Path

from shoestring.internal.CertificateFactory import CertificateFactory
from shoestring.internal.OpensslExecutor import OpensslExecutor
from shoestring.internal.Preparer import Preparer
from shoestring.internal.ShoestringConfiguration import parse_shoestring_configuration


async def run_main(args):
	config = parse_shoestring_configuration(args.config)
	directories = Preparer.DirectoryLocator(None, Path(args.directory))

	ca_key_path = Path(args.ca_key_path).absolute()
	if not ca_key_path.exists():
		raise RuntimeError(f'CA key is required but does not exist at path {ca_key_path}')

	openssl_executor = OpensslExecutor(os.environ.get('OPENSSL_EXECUTABLE', 'openssl'))
	
	# 既存のノード秘密鍵を使用するか、ランダム生成するかを判断
	node_key_path = Path(args.node_key_path).absolute() if args.node_key_path else None
	if node_key_path and not node_key_path.exists():
		raise RuntimeError(f'Node key file is specified but does not exist at path {node_key_path}')

	with CertificateFactory(openssl_executor, ca_key_path, config.node.ca_password) as factory:
		factory.generate_ca_certificate(config.node.ca_common_name)

		# 既存の秘密鍵を使用する場合
		if node_key_path:
			factory.set_node_private_key(node_key_path)
		else:
			# ランダム生成する場合
			factory.generate_random_node_private_key()

		factory.generate_node_certificate(config.node.node_common_name)
		factory.create_node_certificate_chain()

		factory.package(directories.certificates, '' if args.renew_ca else 'node')

def add_arguments(parser):
	parser.add_argument('--config', help=_('argument-help-config'), required=True)
	parser.add_argument('--directory', help=_('argument-help-directory').format(default_path=Path.home()), default=str(Path.home()))
	parser.add_argument('--ca-key-path', help=_('argument-help-ca-key-path'), required=True)
	parser.add_argument('--node-key-path', help='既存のノード秘密鍵のパス', required=False)  # 新しい引数
	parser.add_argument('--renew-ca', help=_('argument-help-renew-certificates-renew-ca'), action='store_true')
	parser.set_defaults(func=run_main)

