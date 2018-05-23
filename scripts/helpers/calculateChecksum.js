'use strict';

const fs = require('fs');
const crypto = require('crypto');

function calculateChecksum(filePath) {
	return new Promise((resolve, reject) => {
		const hash = crypto.createHash('sha256');
		const reader = fs.createReadStream(filePath);

		reader.on('data', chunk => {
			hash.update(chunk);
		});
		reader.on('end', () => {
			resolve(hash.digest('hex'));
		});
		reader.on('error', err => reject(err))
	});
}

module.exports = calculateChecksum;
