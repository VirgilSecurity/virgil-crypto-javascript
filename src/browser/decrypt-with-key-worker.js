export default function(initialEncryptedData, recipientId, privateKeyBase64, privateKeyPassword) {
	const deferred = this.deferred();
	const virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const b64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const b64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	try {
		let recipientIdByteArray = b64decode(recipientId);
		let dataByteArray = b64decode(initialEncryptedData);
		let privateKeyByteArray = b64decode(privateKeyBase64);
		let privateKeyPasswordByteArray = b64decode(privateKeyPassword);
		let decryptedDataByteArray = virgilCipher.decryptWithKey(
			dataByteArray,
			recipientIdByteArray,
			privateKeyByteArray,
			privateKeyPasswordByteArray);
		let decryptedDataBase64 = b64encode(decryptedDataByteArray);

		// cleanup memory to avoid memory leaks
		recipientIdByteArray.delete();
		dataByteArray.delete();
		privateKeyByteArray.delete();
		decryptedDataByteArray.delete();
		privateKeyPasswordByteArray.delete();

		deferred.resolve(decryptedDataBase64);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilCipher.delete();
	}
}
