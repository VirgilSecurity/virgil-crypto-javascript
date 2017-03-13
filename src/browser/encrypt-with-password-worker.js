export default function(initialData, password) {
	const deferred = this.deferred();
	const embedContentInfo = true;
	const virgilCipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	const dataArr = base64decode(initialData);
	const passwordArr = password && base64decode(password);

	try {
		if (passwordArr) {
			virgilCipher.addPasswordRecipient(passwordArr);
		}

		let encryptedData = virgilCipher.encrypt(dataArr, embedContentInfo);
		let encryptedDataBase64 = base64encode(encryptedData);
		encryptedData.delete();
		deferred.resolve(encryptedDataBase64);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilCipher.delete();
		dataArr.delete();
		password && passwordArr.delete();
	}
}
