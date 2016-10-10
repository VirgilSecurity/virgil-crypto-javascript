export default function(initialData, sign, publicKey) {
	const deferred = this.deferred();
	const virgilSigner = new VirgilCryptoWorkerContext.VirgilSigner();
	const base64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;

	try {
		let isVerified = virgilSigner.verify(
			base64decode(initialData),
			base64decode(sign),
			base64decode(publicKey));
		deferred.resolve(isVerified);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		virgilSigner.delete();
	}
}
