export default function(initialData, recipients) {
	const deferred = this.deferred();
	const virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	const dataArr = base64decode(initialData);
	const transformedRecipients = recipients.map(recipient => ({
		recipientId: base64decode(recipient.recipientId),
		publicKey: base64decode(recipient.publicKey)
	}));

	try {
		transformedRecipients.forEach(recipient => {
			virgilCipher.addKeyRecipient(recipient.recipientId, recipient.publicKey);
		});
		const encryptedData = virgilCipher.encrypt(dataArr, true);
		const encryptedDataBase64 = base64encode(encryptedData);
		encryptedData.delete();
		deferred.resolve(encryptedDataBase64);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilCipher.delete();
		dataArr.delete();
		transformedRecipients.forEach(recipient => {
			recipient.recipientId.delete();
			recipient.publicKey.delete();
		})
	}
};
