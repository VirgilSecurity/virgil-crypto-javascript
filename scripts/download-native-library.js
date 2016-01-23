var https = require('https');
var fs = require('fs');
var path = require('path');
var format = require('util').format;


var destFilePath = path.resolve(__dirname + '/../virgil_js.node');
var file = fs.createWriteStream(destFilePath);

var url = 'https://cdn.virgilsecurity.com/packages/nodejs/virgil-crypto-1.2.2-nodejs-%s-%s-%s.node';

var platform = getPlatform();
var arch = getArch();
var nodeVersion = getNodeVersion();

url = format(url, nodeVersion, platform, arch);

console.log('Downloading native build.... %s', url);

https.get(url, function(res) {
	if (res.statusCode != 200) {
		console.error('Platform "%s-%s-%s" is not supported yet', platform, nodeVersion, arch);
		process.exit(-1);
	}

	res.pipe(file);
	res.on('error', abortWithError);
	res.on('end', assertFile);
});

function abortWithError (error) {
	console.error('Download error.');
	console.error(error);
}

function assertFile () {
	if (fs.existsSync(destFilePath)) {
		console.log('Successfully downloaded native build.');
	} else {
		console.error('Platform "%s-%s-%s" is not supported yet', platform, nodeVersion, arch);
	}
}

function getPlatform () {
	if (process.platform === 'darwin') {
		return 'darwin-14.5';
	}

	return process.platform;
}

function getArch () {
	if (process.platform === 'darwin') {
		return 'universal';
	}

	if (process.arch === 'x64') {
		return 'x86_64';
	}

	return process.arch;
}

function getNodeVersion () {
	var versionTokens = process.version.split('.');

	// Use same build for node 4.*.*
	if (versionTokens[0] == 'v4') {
		return '4.1.0';
	}

	// Use same build for node 0.12.*
	if (versionTokens[0] === 'v0' && versionTokens[1] === '12') {
		return '0.12.7';
	}

	return process.version.slice(1);
}
