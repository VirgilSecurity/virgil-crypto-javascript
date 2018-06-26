'use strict';

const path = require('path');
const format = require('util').format;
const log = require('./helpers/log');
const downloadVerifyExtract = require('./helpers/downloadVerifyExtract');

const destFileName = path.resolve(__dirname + '/../src/pythia/browser/asmjs/virgil_crypto_asmjs.js');

downloadVerifyExtract({
	getCdnLink: getCdnLink,
	extractPattern: /lib\/virgil_crypto_asmjs\.js$/,
	writeTo: destFileName
}).then(() => {
	log.success('Successfully downloaded Virgil Pythia asm.js');
}).catch(log.error);

function getCdnLink(libVersion) {
	return format(
		'https://cdn.virgilsecurity.com/virgil-crypto/asmjs/virgil-crypto-%s-asmjs-pythia.tgz',
		libVersion
	);
}
