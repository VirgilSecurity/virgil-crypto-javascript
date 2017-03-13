export default function(initialData, privateKeyBase64, privateKeyPassword) {
	const deferred = this.deferred();
	const virgilSigner = new VirgilCryptoWorkerContext.VirgilSigner();
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	const dataArr = base64decode(initialData);
	const privateKeyArr = base64decode(privateKeyBase64);
	const passwordArr = base64decode(privateKeyPassword);

	try {
		const signArr = virgilSigner.sign(dataArr, privateKeyArr, passwordArr);
		const sign = base64encode(signArr);
		signArr.delete();
		deferred.resolve(sign);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilSigner.delete();
		dataArr.delete();
		privateKeyArr.delete();
		passwordArr.delete();
	}
}
