export default function(initialData, recipientId, publicKey) {
	const deferred = this.deferred();
	const virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	try {
		virgilCipher.addKeyRecipient(base64decode(recipientId), base64decode(publicKey));
		let encryptedDataBase64 = base64encode(virgilCipher.encrypt(base64decode(initialData), true));

		deferred.resolve(encryptedDataBase64);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilCipher.delete();
	}
};
