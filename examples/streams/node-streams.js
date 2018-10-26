const fs = require('fs');
const { Transform } = require('stream');
const { VirgilCrypto } = require('../../dist/virgil-crypto.cjs');

const virgilCrypto = new VirgilCrypto();

function createCipherStream(publicKeys) {
	const cipher = virgilCrypto.createStreamCipher(publicKeys);
	const cipherStream = new Transform({
		transform(chunk, encoding, callback) {
			try {
				this.push(cipher.update(chunk, encoding));
			} catch (err) {
				return callback(err);
			}
			callback();
		},

		flush(callback) {
			try {
				this.push(cipher.final());
			} catch (err) {
				return callback(err);
			}
			callback();
		}
	});

	cipherStream.unshift(cipher.start());
	return cipherStream;
}

function createDecipherStream(privateKey) {
	const decipher = virgilCrypto.createStreamDecipher(privateKey);
	return new Transform({
		transform(chunk, encoding, callback) {
			try {
				this.push(decipher.update(chunk, encoding));
			} catch (err) {
				return callback(err);
			}
			callback();
		},

		flush(callback) {
			try {
				this.push(decipher.final());
			} catch (err) {
				return callback(err);
			}
			callback();
		}
	});
}

function createSignerStream(privateKey) {
	const signer = virgilCrypto.createStreamSigner();
	return new Transform({
		transform(chunk, encoding, callback) {
			try {
				signer.update(chunk, encoding)
				this.push(chunk, encoding);
			} catch (err) {
				return callback(err);
			}
			callback();
		},

		flush(callback) {
			try {
				const signature = signer.sign(privateKey);
				this.emit('signature', signature);
			} catch (err) {
				return callback(err);
			}
			callback();
		}
	});
}

function createVerifierStream(signature, publicKey) {
	const verifier = virgilCrypto.createStreamVerifier(signature);
	return new Transform({
		transform(chunk, encoding, callback) {
			try {
				verifier.update(chunk, encoding);
				this.push(chunk, encoding);
			} catch (err) {
				return callback(err);
			}
			callback();
		},

		flush(callback) {
			try {
				const isVerified = verifier.verify(publicKey);
				this.emit('verification', isVerified);
			} catch (err) {
				return callback(err);
			}
			callback();
		}
	});
}

module.exports = {
	createCipherStream,
	createDecipherStream,
	createSignerStream,
	createVerifierStream
};

if (require.main === module) {
	const keyPair = virgilCrypto.generateKeys();
	const cipherStream = createCipherStream(keyPair.publicKey);
	const signerStream = createSignerStream(keyPair.privateKey);

	const plaintextReadStream = fs.createReadStream(__dirname + '/data.txt');
	const ciphertextWriteStream = fs.createWriteStream(__dirname + '/data.encrypted');

	plaintextReadStream.pipe(cipherStream).pipe(signerStream).pipe(ciphertextWriteStream);

	signerStream.on('signature', signature => {
		console.log('Signature:', signature.toString('base64'));

		const decipherStream = createDecipherStream(keyPair.privateKey);
		const verifierStream = createVerifierStream(signature, keyPair.publicKey);

		const ciphertextReadStream = fs.createReadStream(__dirname + '/data.encrypted');
		const plaintextWriteStream = fs.createWriteStream(__dirname + '/data.decrypted.txt');

		ciphertextReadStream.pipe(verifierStream).pipe(decipherStream).pipe(plaintextWriteStream);

		verifierStream.on('verification', isVerified => {
			console.log(`Signature is ${isVerified ? 'verified' : 'not verified'}`);
		});
	});
}
