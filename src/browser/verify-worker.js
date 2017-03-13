export default function(initialData, sign, publicKey) {
	const deferred = this.deferred();
	const virgilSigner = new VirgilCryptoWorkerContext.VirgilSigner();
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;

	const dataArr = base64decode(initialData);
	const signArr = base64decode(sign);
	const publicKeyArr = base64decode(publicKey);

	try {
		let isVerified = virgilSigner.verify(dataArr, signArr, publicKeyArr);
		deferred.resolve(isVerified);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilSigner.delete();
		dataArr.delete();
		signArr.delete();
		publicKeyArr.delete();
	}
}
