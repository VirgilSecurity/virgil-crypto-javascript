export default function(initialData, privateKeyBase64, privateKeyPassword) {
	const deferred = this.deferred();
	const virgilSigner = new VirgilCryptoWorkerContext.VirgilSigner();
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const base64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;

	try {
		let sign = base64encode(
			virgilSigner.sign(
				base64decode(initialData),
				base64decode(privateKeyBase64),
				base64decode(privateKeyPassword)));

		deferred.resolve(sign);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilSigner.delete();
	}
}
