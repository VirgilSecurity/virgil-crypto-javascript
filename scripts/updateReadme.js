'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { version } = require('../package.json');

const SCRIPT_REGEX = /<script[\s\S]*?>[\s\S]*?<\/script>/gi;

const getScript = ({ version, integrity }) =>
`<script
src="https://cdn.virgilsecurity.com/packages/javascript/crypto/${version}/virgil-crypto.browser.umd.min.js"
integrity="${integrity}"
crossorigin="anonymous"></script>`;

calculateBundleIntegrity()
	.then(integrity => getScript({ version, integrity }))
	.then(script => {
		const readmePath = path.resolve(__dirname, '../README.md');
		let readme = fs.readFileSync(readmePath, { encoding: 'utf8' });

		readme = readme.replace(SCRIPT_REGEX, script);

		fs.writeFileSync(readmePath, readme, { encoding: 'utf8' });
	})
	.catch(e => {
		console.error(e);
		process.exit(1);
	});

function calculateBundleIntegrity() {
	return new Promise((resolve, reject) => {
		const hash = crypto.createHash('sha256');
		const bundle = fs.createReadStream(
			path.resolve(__dirname, '../dist/virgil-crypto.browser.umd.min.js')
		);

		bundle.on('readable', () => {
			let chunk;
			while ((chunk = bundle.read()) !== null) {
				hash.update(chunk);
			}
		}).on('end', () => {
			resolve('sha256-' + hash.digest('base64'));
		}).on('error', (e) => {
			reject(e);
		});
	});
}


