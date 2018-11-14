'use strict';

const path = require('path');
const format = require('util').format;
const log = require('./helpers/log');
const downloadVerifyExtract = require('./helpers/downloadVerifyExtract');
const VIRGIL_CRYPTO_LATEST_VERSION = require('./helpers/constants').VIRGIL_CRYPTO_LATEST_VERSION;

const destFileName = path.resolve(__dirname + '/../virgil_crypto_node.node');

const isWindows = process.platform === 'win32';


// mapping from current node's _ABI_ version number to the latest version of
// Virgil Crypto with pre-built addons on cdn
const ModuleVersionToLibVersion = {
	'67': VIRGIL_CRYPTO_LATEST_VERSION, // Node.js 11
	'64': VIRGIL_CRYPTO_LATEST_VERSION, // Node.js 10
	'59': '2.6.1',                      // Node.js 9
	'57': VIRGIL_CRYPTO_LATEST_VERSION, // Node.js 8
	'51': '2.6.1',                      // Node.js 7
	'48': VIRGIL_CRYPTO_LATEST_VERSION, // Node.js 6,
	'46': '2.6.1'                       // Node.js 4
};

// mapping from current node's _ABI_ version number to the Node.js version
// with pre-built addons on cdn
const ModuleVersionToNodeVersion = {
	'67': '11.1.0',
	'64': '10.9.0',
	'59': isWindows ? '9.11.2' : '9.11.1',
	'57': '8.12.0',
	'51': '7.10.1',
	'48': '6.14.4',
	'46': '4.9.1'
};

downloadVerifyExtract({
	url: getCdnLink(),
	extractPattern: /\.node$/,
	writeTo: destFileName
}).then(() => {
	log.success('Successfully downloaded Virgil Crypto Node.js Addon');
}).catch((e) => {
	if (e.status && e.status === 404) {
		log.error(` Failed to download Virgil Crypto Node.js Addon.
		Your Node.js version and/or OS is not supported by virgil-crypto.
		If you only intend to use virgil-crypto in a browser environment, ignore this error.
		`);
	} else {
		log.error(e);
	}
});

function getCdnLink() {
	const libVersion = getLibVersion();
	const nodeVersion = getNodeVersion();
	const platform = getPlatform();
	const arch = getArch();

	return format(
		'https://cdn.virgilsecurity.com/virgil-crypto/nodejs/virgil-crypto-%s-nodejs-%s-%s-%s.%s',
		libVersion,
		nodeVersion,
		platform,
		arch,
		isWindows ? 'zip' : 'tgz'
	);
}

function getPlatform () {
	if (process.platform === 'darwin') {
		return 'darwin-18.0';
	}

	if (isWindows) {
		return 'windows-6.3';
	}

	return process.platform;
}

function getArch () {
	if (process.arch === 'x64' && !isWindows) {
		return 'x86_64';
	}

	if (process.arch === 'ia32' && isWindows) {
		return 'x86';
	}

	return process.arch;
}

function getNodeVersion () {
	return ModuleVersionToNodeVersion[process.versions.modules] || process.version.slice(1);
}

function getLibVersion () {
	return ModuleVersionToLibVersion[process.versions.modules] || VIRGIL_CRYPTO_LATEST_VERSION;
}
