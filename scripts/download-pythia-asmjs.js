'use strict';

const path = require('path');
const format = require('util').format;
const log = require('./helpers/log');
const downloadVerifyExtract = require('./helpers/downloadVerifyExtract');
const VIRGIL_CRYPTO_LATEST_VERSION = require('./helpers/constants').VIRGIL_CRYPTO_LATEST_VERSION;

const destFileName = path.resolve(__dirname + '/../src/lib/virgil_crypto_pythia_asmjs.js');

downloadVerifyExtract({
	url: getCdnLink(),
	extractPattern: /lib\/virgil_crypto_asmjs\.js$/,
	writeTo: destFileName
}).then(() => {
	log.success('Successfully downloaded Virgil Pythia asm.js');
}).catch(log.error);

function getCdnLink() {
	return format(
		'https://cdn.virgilsecurity.com/virgil-crypto/asmjs/virgil-crypto-%s-asmjs-pythia.tgz',
		VIRGIL_CRYPTO_LATEST_VERSION
	);
}
