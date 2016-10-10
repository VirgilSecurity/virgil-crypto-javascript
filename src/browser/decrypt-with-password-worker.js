export default function(initialEncryptedData, password) {
	const deferred = this.deferred();
	const virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const b64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const b64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	try {
		let dataByteArray = b64decode(initialEncryptedData);
		let passwordByteArray = b64decode(password);
		let decryptedDataByteArray = virgilCipher.decryptWithPassword(dataByteArray, passwordByteArray);
		let decryptedData = b64encode(decryptedDataByteArray);

		// cleanup memory to avoid memory leaks
		dataByteArray.delete();
		passwordByteArray.delete();
		decryptedDataByteArray.delete();

		deferred.resolve(decryptedData);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilCipher.delete();
	}
};
