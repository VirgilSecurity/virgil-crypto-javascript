export default function(password, keysType) {
	const deferred = this.deferred();
	const KeyPair = VirgilCryptoWorkerContext.VirgilKeyPair;
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;

	const passwordByteArray = base64decode(password);

	try {

		let virgilKeys;
		if (keysType) {
			virgilKeys = KeyPair.generate(KeyPair.Type[keysType], passwordByteArray);
		} else {
			virgilKeys = KeyPair.generateRecommended(passwordByteArray);
		}

		const publicKey = virgilKeys.publicKey().toUTF8();
		const privateKey = virgilKeys.privateKey().toUTF8();

		// cleanup memory to avoid memory leaks
		virgilKeys.delete();

		deferred.resolve({ publicKey: publicKey, privateKey: privateKey });
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		passwordByteArray.delete();
	}
};
