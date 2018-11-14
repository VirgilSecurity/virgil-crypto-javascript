'use strict';

const fs = require('fs');
const downloadToTemporaryFile = require('./downloadToTemporaryFile');
const calculateChecksum = require('./calculateChecksum');
const extractFileFromArchive = require('./extractFileFromArchive');

function downloadVerifyExtract(params) {
	const url = params.url;
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
