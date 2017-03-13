export default function(data, privateKey, recipients) {
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;
	const ByteArray = VirgilCryptoWorkerContext.VirgilByteArray;

	const deferred = this.deferred();
	const signer = new VirgilCryptoWorkerContext.VirgilSigner();
	const cipher = new VirgilCryptoWorkerContext.VirgilCipher();

	const dataArr = base64decode(data);
	const privateKeyArr = base64decode(privateKey);
	const passwordArr = ByteArray.fromUTF8('');
	const signatureKeyArr = ByteArray.fromUTF8('VIRGIL-DATA-SIGNATURE');
	const transformedRecipients = recipients.map(recipient => ({
		id: base64decode(recipient.recipientId),
		publicKey: base64decode(recipient.publicKey)
	}));

	try {
		const signatureArr = signer.sign(
			dataArr,
			privateKeyArr,
			passwordArr);

		cipher
			.customParams()
			.setData(signatureKeyArr, signatureArr);

		transformedRecipients.forEach(recipient => {
			cipher.addKeyRecipient(recipient.id, recipient.publicKey);
		});

		const cipherDataArr = cipher.encrypt(dataArr, true);
		const cipherData = base64encode(cipherDataArr);

		 signatureArr.delete();
		cipherDataArr.delete();

		deferred.resolve(cipherData);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		signer.delete();
		cipher.delete();
		dataArr.delete();
		privateKeyArr.delete();
		passwordArr.delete();
		signatureKeyArr.delete();
		transformedRecipients.forEach(recipient => {
			recipient.id.delete();
			recipient.publicKey.delete();
		});
	}
}

