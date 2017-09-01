import VC from '../utils/crypto-module';
import { bufferToByteArray, isBuffer } from '../utils/crypto-utils';

export function makePFSPrivateKey(privateKey) {
	if (!privateKey) {
		return null;
	}

	const privateKeyBytes = isBuffer(privateKey)
		? privateKey
		: ( isBuffer(privateKey.privateKey )
				? privateKey.privateKey
				: null
		);
	const passwordBytes = isBuffer(privateKey.password)
		? privateKey.password
		: null;

	if (privateKeyBytes === null) {
		return null;
	}

	return new VC.VirgilPFSPrivateKey(
		bufferToByteArray(privateKeyBytes),
		passwordBytes ? bufferToByteArray(passwordBytes) : new VC.VirgilByteArray()
	);
}

export function makePFSPublicKey(publicKey) {
	if (!publicKey || !isBuffer(publicKey)) {
		return null;
	}

	return new VC.VirgilPFSPublicKey(bufferToByteArray(publicKey));
}

export const emptyPFSPrivateKey = () => new VC.VirgilPFSPrivateKey(
	new VC.VirgilByteArray,
	new VC.VirgilByteArray
);

export const emptyPFSPublicKey = () => new VC.VirgilPFSPublicKey(
	new VC.VirgilByteArray
);
