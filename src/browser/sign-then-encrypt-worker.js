export default function(data, privateKey, recipients) {
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;
	const ByteArray = VirgilCryptoWorkerContext.VirgilByteArray;

	const deferred = this.deferred();
	const signer = new VirgilCryptoWorkerContext.VirgilSigner();
	const cipher = new VirgilCryptoWorkerContext.VirgilCipher();

	const dataArr = base64decode(data);
	const privateKeyArr = base64decode(privateKey.privateKey);
	const privateKeyPasswordArr = base64decode(privateKey.password);
	const privateKeyIdArr = privateKey.recipientId && base64decode(privateKey.recipientId);

	const signatureKeyArr = ByteArray.fromUTF8('VIRGIL-DATA-SIGNATURE');
	const signerIdKeyArr = ByteArray.fromUTF8('VIRGIL-DATA-SIGNER-ID');

	const transformedRecipients = recipients.map(recipient => ({
		recipientId: base64decode(recipient.recipientId),
		publicKey: base64decode(recipient.publicKey)
	}));

	try {
		const signatureArr = signer.sign(
			dataArr,
			privateKeyArr,
			privateKeyPasswordArr);

		cipher
			.customParams()
			.setData(signatureKeyArr, signatureArr);

		if (privateKeyIdArr) {
			cipher.customParams()
				.setData(signerIdKeyArr, privateKeyIdArr);
		}

		transformedRecipients.forEach(recipient => {
			cipher.addKeyRecipient(recipient.recipientId, recipient.publicKey);
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
		privateKeyPasswordArr.delete();
		privateKeyIdArr && privateKeyIdArr.delete();
		signatureKeyArr.delete();
		signerIdKeyArr.delete();
		transformedRecipients.forEach(recipient => {
			recipient.recipientId.delete();
			recipient.publicKey.delete();
		});
	}
}

