export default function(data, privateKey, recipients) {
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;
	const ByteArray = VirgilCryptoWorkerContext.VirgilByteArray;

	const deferred = this.deferred();
	const signer = new VirgilCryptoWorkerContext.VirgilSigner();
	const cipher = new VirgilCryptoWorkerContext.VirgilCipher();

	const dataByteArray = base64decode(data);

	try {
		let signature = signer.sign(
			dataByteArray,
			base64decode(privateKey),
			ByteArray.fromUTF8(''));

		cipher
			.customParams()
			.setData(ByteArray.fromUTF8('VIRGIL-DATA-SIGNATURE'), signature);

		recipients.forEach(function (recipient) {
			cipher.addKeyRecipient(
				base64decode(recipient.recipientId),
				base64decode(recipient.publicKey));
		});

		deferred.resolve(base64encode(cipher.encrypt(dataByteArray, true)));
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		signer.delete();
		cipher.delete();
	}
}

