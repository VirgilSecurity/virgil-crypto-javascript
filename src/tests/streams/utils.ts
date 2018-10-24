import { cryptoWrapper } from '../../virgilCryptoWrapper';
import { VirgilPrivateKey } from '../../VirgilPrivateKey';
import { VirgilPublicKey } from '../../VirgilPublicKey';

if (!Symbol.asyncIterator) {
	(Symbol as any).asyncIterator = Symbol.for('Symbol.asyncIterator');
}

export async function* createAsyncIterable<T>(arr: T[]) {
	for (const item of arr) {
		yield item;
	}
}

export function splitIntoChunks (input: Buffer, chunkSize: number): Buffer[] {
	const chunks = [];
	let offset = 0;
	while(offset < input.byteLength) {
		chunks.push(input.slice(offset, offset += chunkSize));
	}
	return chunks;
}

export function createVirgilKeyPair() {
	const keyPair = cryptoWrapper.generateKeyPair();
	const keyPairId = Buffer.from(`key_pair_id_${Math.random().toString(36).substr(6)}`);

	return {
		privateKey: new VirgilPrivateKey(keyPairId, keyPair.privateKey),
		publicKey: new VirgilPublicKey(keyPairId, keyPair.publicKey)
	};
}
