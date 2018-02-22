var https = require('https');
var fs = require('fs');
var path = require('path');
var format = require('util').format;

var destFilePath = path.resolve(__dirname + '/../virgil_js.node');

var url = '/packages/nodejs/virgil-crypto-%s-nodejs-%s-%s-%s.node';

var cryptoVersion;
var nodeVersion = getNodeVersion();
var platform = getPlatform();
var arch = getArch();

if (nodeVersion.indexOf('5') === 0) {
	cryptoVersion = '2.2.5';
	if (process.platform === 'darwin') {
		platform = 'darwin-16.7';
	}
} else {
	cryptoVersion = '2.3.0'
}

url = format(url, cryptoVersion, nodeVersion, platform, arch);

console.log('Downloading C++ Addon.... %s', url);

var options = {
	protocol: 'https:',
	hostname: 'cdn.virgilsecurity.com',
	path: url,
	agent: new https.Agent({ keepAlive: true })
};

var file = fs.createWriteStream(destFilePath);

var req = https.get(options, function(res) {
	if (res.statusCode === 404) {
		abortWithError(
			'Platform "nodejs-' + nodeVersion + '-' + platform + '-' + arch + '" is not supported.'
		);
	}

	if (res.statusCode !== 200) {
		abortWithError('Unexpected server response: ' + res.statusCode + '.');
	}

	res.pipe(file);
	res.on('error', abortWithError);
	res.on('end', function () {
		console.log('C++ Addon downloaded successfully.');
	});
});

req.on('error', abortWithError);

function abortWithError (error) {
	file.close();
	fs.unlinkSync(destFilePath);

	console.error('\x1b[31m', 'Failed to download Virgil Crypto C++ Addon', '\x1b[0m');
	console.error('\x1b[31m', 'Your Node.js version or OS is not supported by virgil-crypto', '\x1b[0m');
	console.error(error);
	process.exit(1);
}

function getPlatform () {
	if (process.platform === 'darwin') {
		return 'darwin-17.4';
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
	var versionTokens = process.version.split('.');

	// Use same build for node 4.*.*
	if (versionTokens[0] == 'v4') {
		return '4.8.7';
	}

	// Use same build for node 5.*.*
	if (versionTokens[0] == 'v5') {
		return '5.9.1';
	}

	// Use same build for node 6.*.*
	if (versionTokens[0] == 'v6') {
		return '6.13.0';
	}

	// Use same build for node 7.*.*
	if (versionTokens[0] == 'v7') {
		return '7.10.1';
	}

	// Use same build for node 8.*.*
	if (versionTokens[0] == 'v8') {
		return '8.9.4';
	}

	// Use same build for node 9.*.*
	if (versionTokens[0] == 'v9') {
		return '9.5.0';
	}

	return process.version.slice(1);
}
