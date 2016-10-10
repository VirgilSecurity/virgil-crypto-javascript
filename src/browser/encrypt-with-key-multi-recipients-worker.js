export default function(initialData, recipients) {
	const deferred = this.deferred();
	const virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	try {
		recipients.forEach((recipient) => {
			virgilCipher.addKeyRecipient(base64decode(recipient.recipientId), base64decode(recipient.publicKey));
		});
		const encryptedDataBase64 = base64encode(virgilCipher.encrypt(base64decode(initialData), true));
		deferred.resolve(encryptedDataBase64);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilCipher.delete();
	}
};
