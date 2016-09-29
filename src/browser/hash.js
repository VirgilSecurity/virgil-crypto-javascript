import VirgilCrypto from './utils/crypto-module';
import * as u from './utils/crypto-utils';

export function hash(data, algorithm) {
	algorithm = algorithm || VirgilCrypto.VirgilHashAlgorithm.SHA256;
	const virgilHash = new VirgilCrypto.VirgilHash(algorithm);
	const hash = virgilHash.hash(u.toByteArray(data));
	return u.byteArrayToBuffer(hash);
}
