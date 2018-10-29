'use strict';

const path = require('path');
const format = require('util').format;
const log = require('./helpers/log');
const downloadVerifyExtract = require('./helpers/downloadVerifyExtract');

const destFileName = path.resolve(__dirname + '/../virgil_crypto_node.node');

const isWindows = process.platform === 'win32';

const ModuleVersionToNodeVersion = {
	'64': isWindows ? '10.4.1' : '10.1.0',
	'59': isWindows ? '9.11.2' : '9.11.1',
	'57': isWindows ? '8.11.3' : '8.11.2',
	'51': '7.10.1',
	'48': isWindows ? '6.14.3' : '6.14.2',
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
