'use strict';

const fs = require('fs');
const downloadToTemporaryFile = require('./downloadToTemporaryFile');
const calculateChecksum = require('./calculateChecksum');
const extractFileFromArchive = require('./extractFileFromArchive');
const log = require('./log');
const pkg = require('../../package');

const cryptoVersion = process.env.VIRGIL_CRYPTO_LIB_VERSION || pkg['virgil-crypto-lib-version'];
if (!cryptoVersion) {
	log.error(new Error(
		'Version of crypto library to download cannot be resolved. ' +
		'It must be specified as either an environment variable `VIRGIL_CRYPTO_LIB_VERSION` ' +
		'or a property `virgil-crypto-lib-version` in package.json'
	));
	process.exit(1);
}

function downloadVerifyExtract(params) {
	const url = params.getCdnLink(cryptoVersion);
	const checksumUrl = url + '.sha256';

	return Promise.all([
		downloadToTemporaryFile(url),
		downloadToTemporaryFile(checksumUrl)
	]).then(fileNames => {
		const archiveFileName = fileNames[0];
		const checksumFileName = fileNames[1];

		return calculateChecksum(archiveFileName)
			.then(actualChecksum => {
				const expectedChecksum = fs.readFileSync(checksumFileName, { encoding: 'utf8' });
				if (actualChecksum.toLowerCase().trim() !== expectedChecksum.toLowerCase().trim()) {
					throw new Error('Checksum verification has failed');
				}

				return archiveFileName;
			});
	}).then(archiveFileName => extractFileFromArchive({
		path: archiveFileName,
		pattern: params.extractPattern,
		writeTo: params.writeTo,
		isZip: url.slice(-3) === 'zip'
	}));
}

module.exports = downloadVerifyExtract;
