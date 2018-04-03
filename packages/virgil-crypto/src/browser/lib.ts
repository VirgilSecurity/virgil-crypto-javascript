import { lib } from './asmjs';
import { wrapper } from './helpers';

wrapper.createSafeInstanceMethods(lib.VirgilCipher, [ 'addKeyRecipient', 'encrypt', 'decryptWithKey' ]);
wrapper.createSafeInstanceMethods(lib.VirgilSigner, [ 'sign', 'verify' ]);
wrapper.createSafeInstanceMethods(lib.VirgilHash, [ 'hash' ]);
wrapper.createSafeInstanceMethods(lib.VirgilCustomParams, [ 'setData', 'getData' ]);
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

// creates instances of VirgilCipher that will be automatically
// deleted on the next tick of the event loop
lib.createVirgilCipher = () => new lib.VirgilCipher().deleteLater();

// creates instances of VirgilSigner that will be automatically
// deleted on the next tick of the event loop
lib.createVirgilSigner = () => new lib.VirgilSigner().deleteLater();

// creates instances of VirgilHash that will be automatically
// deleted on the next tick of the event loop
lib.createVirgilHash = (...args: any[]) => new lib.VirgilHash(...args).deleteLater();

export { lib };
