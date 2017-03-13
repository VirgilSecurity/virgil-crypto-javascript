export default function(initialEncryptedData, password) {
	const deferred = this.deferred();
	const virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const b64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const b64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	const dataByteArray = b64decode(initialEncryptedData);
	const passwordByteArray = b64decode(password);

	try {

		let decryptedDataByteArray = virgilCipher.decryptWithPassword(dataByteArray, passwordByteArray);
		let decryptedData = b64encode(decryptedDataByteArray);

		// cleanup memory to avoid memory leaks
		decryptedDataByteArray.delete();

		deferred.resolve(decryptedData);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilCipher.delete();
		dataByteArray.delete();
		passwordByteArray.delete();
	}
};
