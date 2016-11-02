export default function(cipherData, recipientId, privateKey, publicKey) {
	const b64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const b64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;
	const ByteArray = VirgilCryptoWorkerContext.VirgilByteArray;

	const deferred = this.deferred();

	const cipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const signer = new VirgilCryptoWorkerContext.VirgilSigner();

	try {
		let plainData = cipher.decryptWithKey(
			b64decode(cipherData),
			b64decode(recipientId),
			b64decode(privateKey),
			ByteArray.fromUTF8(''));

		let signature = cipher
			.customParams()
			.getData(ByteArray.fromUTF8('VIRGIL_DATA_SIGN'));

		let isValid = signer.verify(plainData, signature, b64decode(publicKey));
		if (!isValid) {
			deferred.reject('Signature verification has failed.');
		}

		deferred.resolve(b64encode(plainData));
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		cipher.delete();
		signer.delete();
	}
}
