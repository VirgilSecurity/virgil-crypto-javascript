'use strict';

const fs = require('fs');
const zlib = require('zlib');
const tar = require('tar');
const yauzl = require('yauzl');

module.exports = extractFileFromArchive;

function extractFileFromArchive(params) {
	if (params.isZip) {
		return extractFromZip(params.path, params.writeTo, params.pattern);
	}

	return extractFromTgz(params.path, params.writeTo, params.pattern);
}

function extractFromTgz(sourcePath, targetPath, pattern) {
	return new Promise((resolve, reject) => {
		fs.createReadStream(sourcePath)
			.pipe(new zlib.Unzip())
			.pipe(new tar.Parse())
			.on('entry', entry => {
				if (pattern.test(entry.path)) {
					entry.pipe(fs.createWriteStream(targetPath))
				} else {
					entry.resume();
				}
			})
			.on('end', resolve)
			.on('error', reject);
	});
}

function extractFromZip(sourcePath, targetPath, pattern) {
	return new Promise((resolve, reject) => {
		yauzl.open(sourcePath, (err, zipFile) => {
			if (err) {
				return reject(err);
			}

			zipFile.on('entry', entry => {
				if (pattern.test(entry.fileName)) {
					// the file we are looking for
					zipFile.openReadStream(entry, (err, readStream) => {
						if (err) {
							return reject(err);
						}

						readStream.pipe(fs.createWriteStream(targetPath));
					});
				}
			});

			zipFile
				.on('end', resolve)
				.on('error', reject);
		});
	});
}
