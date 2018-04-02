/// <reference path="../declarations.d.ts" />
import lib from '../../virgil_crypto_node.node';
import { wrapper } from './helpers';

wrapper.createSafeInstanceMethods(lib.VirgilCipher, [ 'addKeyRecipient', 'encrypt', 'decryptWithKey' ]);
wrapper.createSafeInstanceMethods(lib.VirgilSigner, [ 'sign', 'verify' ]);
wrapper.createSafeInstanceMethods(lib.VirgilHash, [ 'hash' ]);
wrapper.createSafeInstanceMethods(lib.VirgilKeyPair, [ 'privateKey', 'publicKey' ]);
wrapper.createSafeStaticMethods(lib.VirgilKeyPair, [
	'generate',
	'generateRecommended',
	'decryptPrivateKey',
	'encryptPrivateKey',
	'extractPublicKey',
	'privateKeyToDER',
	'publicKeyToDER'
]);

export { lib };
