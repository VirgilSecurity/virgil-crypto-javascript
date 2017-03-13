export default function(initialEncryptedData, recipientId, privateKeyBase64, privateKeyPassword) {
	const deferred = this.deferred();
	const virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const b64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const b64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	const recipientIdByteArray = b64decode(recipientId);
	const dataByteArray = b64decode(initialEncryptedData);
	const privateKeyByteArray = b64decode(privateKeyBase64);
	const privateKeyPasswordByteArray = b64decode(privateKeyPassword);

	try {

		let decryptedDataByteArray = virgilCipher.decryptWithKey(
			dataByteArray,
			recipientIdByteArray,
			privateKeyByteArray,
			privateKeyPasswordByteArray);
		let decryptedDataBase64 = b64encode(decryptedDataByteArray);

		// cleanup memory to avoid memory leaks
		decryptedDataByteArray.delete();
		deferred.resolve(decryptedDataBase64);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilCipher.delete();
		recipientIdByteArray.delete();
		dataByteArray.delete();
		privateKeyByteArray.delete();
		privateKeyPasswordByteArray.delete();
	}
}
