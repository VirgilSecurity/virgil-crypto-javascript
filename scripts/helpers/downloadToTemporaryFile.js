'use strict';

const fs = require('fs');
const fetch = require('node-fetch');
const tempy = require('tempy');

function downloadToTemporaryFile(url) {
	return fetch(url).then(res => {
		if (!res.ok) {
			const error = new Error(
				`Failed to download ${url}. Server responded with ${res.status} - ${res.statusText}`
			);
			error.status = res.status;
			error.statusText = res.statusText;

			throw error;
		}

		return new Promise((resolve, reject) => {
			const targetFile = tempy.file();
			const writer = fs.createWriteStream(targetFile);
			res.body.pipe(writer);
			res.body
				.on('end', () => {
					resolve(targetFile);
				})
				.on('error', (err) => {
					writer.close();
					reject(err);
				});
		});
	});
}

module.exports = downloadToTemporaryFile;
