'use strict';

const path = require('path');
const format = require('util').format;
const log = require('./helpers/log');
const downloadVerifyExtract = require('./helpers/downloadVerifyExtract');

const destFileName = path.resolve(__dirname + '/../virgil_crypto_node.node');

const ModuleVersionToNodeVersion = {
	'64': '10.1.0',
	'59': '9.11.1',
	'57': '8.11.2',
	'51': '7.10.1',
	'48': '6.14.2',
	'46': '4.9.1'
};

downloadVerifyExtract({
	getCdnLink: getCdnLink,
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

function getCdnLink(libVersion) {
	const nodeVersion = getNodeVersion();
	const platform = getPlatform();
	const arch = getArch();

	return format(
		'https://cdn.virgilsecurity.com/virgil-crypto/nodejs/virgil-crypto-%s-nodejs-%s-%s-%s.%s',
		libVersion,
		nodeVersion,
		platform,
		arch,
		process.platform === 'win32' ? 'zip' : 'tgz'
	);
}

function getPlatform () {
	if (process.platform === 'darwin') {
		return 'darwin-17.5';
	}

	if (process.platform === 'win32') {
		return 'windows-6.3';
	}

	return process.platform;
}

function getArch () {
	if (process.arch === 'x64' && process.platform !== 'win32') {
		return 'x86_64';
	}

	if (process.arch === 'ia32' && process.platform === 'win32') {
		return 'x86';
	}

	return process.arch;
}

function getNodeVersion () {
	return ModuleVersionToNodeVersion[process.versions.modules] || process.version.slice(1);
}
