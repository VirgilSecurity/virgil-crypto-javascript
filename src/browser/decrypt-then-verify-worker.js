export default function(cipherData, recipientId, privateKey, publicKey) {
	const b64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const b64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;
	const ByteArray = VirgilCryptoWorkerContext.VirgilByteArray;

	const deferred = this.deferred();

	const cipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const signer = new VirgilCryptoWorkerContext.VirgilSigner();

	const cipherDataArr = b64decode(cipherData);
	const recipientIdArr = b64decode(recipientId);
	const privateKeyArr = b64decode(privateKey);
	const passwordArr = ByteArray.fromUTF8('');
	const publicKeyArr = b64decode(publicKey);
	const signatureKeyArr = ByteArray.fromUTF8('VIRGIL-DATA-SIGNATURE');

	try {
		let plainDataArr = cipher.decryptWithKey(
			cipherDataArr,
			recipientIdArr,
			privateKeyArr,
			passwordArr);

		let signature = cipher
			.customParams()
			.getData(signatureKeyArr);

		let isValid = signer.verify(plainDataArr, signature, publicKeyArr);
		if (!isValid) {
			deferred.reject('Signature verification has failed.');
		}

		let plainData = b64encode(plainDataArr);
		plainDataArr.delete();
		deferred.resolve(plainData);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		cipher.delete();
		signer.delete();
		cipherDataArr.delete();
		recipientIdArr.delete();
		privateKeyArr.delete();
		passwordArr.delete();
		publicKeyArr.delete();
		signatureKeyArr.delete();
	}
}
