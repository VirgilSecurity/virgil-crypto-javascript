export default function(cipherData, recipientId, privateKey, publicKeys) {
	const b64decode = VirgilCryptoWorkerContext.VirgilBase64.decode;
	const b64encode = VirgilCryptoWorkerContext.VirgilBase64.encode;
	const ByteArray = VirgilCryptoWorkerContext.VirgilByteArray;

	const deferred = this.deferred();

	const cipher = new VirgilCryptoWorkerContext.VirgilCipher();
	const signer = new VirgilCryptoWorkerContext.VirgilSigner();

	const cipherDataArr = b64decode(cipherData);
	const privateKeyArr = b64decode(privateKey.privateKey);
	const privateKeyPasswordArr = b64decode(privateKey.password);
	const recipientIdArr = b64decode(recipientId);
	const signatureKeyArr = ByteArray.fromUTF8('VIRGIL-DATA-SIGNATURE');

	const verifiers = publicKeys.map(publicKey => ({
		recipientId: b64decode(publicKey.recipientId || ''),
		publicKey: b64decode(publicKey.publicKey)
	}));

	try {
		const plainDataArr = cipher.decryptWithKey(
			cipherDataArr,
			recipientIdArr,
			privateKeyArr,
			privateKeyPasswordArr);

		const signature = cipher
			.customParams()
			.getData(signatureKeyArr);

		let isValid, signerId;

		if (verifiers.length === 1) {
			isValid = verifyWithSingleKey(signer, plainDataArr, signature, verifiers[0]);
		} else {
			signerId = tryGetSignerId(cipher);
			isValid = verifyWithMultipleKeys(signer, plainDataArr, signature, verifiers, signerId);
		}

		if (!isValid) {
			deferred.reject('Signature verification has failed.');
		}

		let plainData = b64encode(plainDataArr);
		plainDataArr.delete();
		signature.delete();
		signerId && signerId.delete();

		deferred.resolve(plainData);
	} catch (e) {
		deferred.reject(e.message);
	} finally {
		cipher.delete();
		signer.delete();
		cipherDataArr.delete();
		recipientIdArr.delete();
		privateKeyArr.delete();
		privateKeyPasswordArr.delete();
		verifiers.forEach(verifier => {
			verifier.publicKey.delete();
			verifier.recipientId.delete();
		});
		signatureKeyArr.delete();
	}

	function verifyWithSingleKey(signer, data, signature, key) {
		return signer.verify(data, signature, key.publicKey);
	}

	function verifyWithMultipleKeys(signer, data, signature, keys, signerId) {
		if (signerId) {
			// find the public key corresponding to signer id from metadata
			var signerPublicKey = find(keys, key =>
				b64encode(signerId) === b64encode(key.recipientId));

			return signerPublicKey ?
				signer.verify(data, signature, signerPublicKey.publicKey) :
				false;
		}

		// no signer id in metadata, try all public keys in sequence
		return keys.some(function (key) {
			return signer.verify(data, signature, key.publicKey);
		});
	}

	function tryGetSignerId(cipher) {
		const customParams = cipher.customParams();
		const signerIdKeyArr = ByteArray.fromUTF8('VIRGIL-DATA-SIGNER-ID');
		try {
			return customParams.getData(signerIdKeyArr);
		} catch (e) {
			return null;
		} finally {
			signerIdKeyArr.delete();
		}
	}

	function find(array, predicate) {
		const list = Object(array);
		const length = list.length >>> 0;
		let value;

		for (let i = 0; i < length; i++) {
			value = list[i];
			if (predicate.call(null, value, i, list)) {
				return value;
			}
		}

		return undefined;
	}
}
