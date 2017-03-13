export default function(initialData, recipientId, publicKey) {
	const deferred = this.deferred();
	const virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	const dataArr = base64decode(initialData);
	const recipientIdArr = base64decode(recipientId);
	const publicKeyArr = base64decode(publicKey);

	try {
		virgilCipher.addKeyRecipient(recipientIdArr, publicKeyArr);
		const encryptedData = virgilCipher.encrypt(dataArr, true);
		const encryptedDataBase64 = base64encode(encryptedData);
		encryptedData.delete();
		deferred.resolve(encryptedDataBase64);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilCipher.delete();
		dataArr.delete();
		recipientIdArr.delete();
		publicKeyArr.delete();
	}
};
