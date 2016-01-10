var https = require('https');
var fs = require('fs');
var path = require('path');
var getos = require('getos');
var format = require('util').format;

var destFilePath = path.resolve(__dirname + '/../virgil_js.node');
var file = fs.createWriteStream(destFilePath);

var platformsMap = {
	'darwin': 'darwin',
	'win32': 'win',
	'Ubuntu Linux': 'ubuntu',
	'Centos': 'centos',
	'Debian': 'debian'
};

getos(function downloadOsSpecificBuild (err, os) {
	// node version - platform - arch
	var url = 'https://downloads.virgilsecurity.com/packages/nodejs/crypto_lib-1.1.0_nodejs-%s_%s-%s.node';

	var dist = os.dist || os.os;
	var platform = platformsMap[dist];


	if (!platform) {
		console.error('Platform is not supported');
		process.exit(-1);
	}

	url = format(url, getNodeBuildVersion(), platform, process.arch);

	console.log('Downloading native build.... %s', url);

	https.get(url, function(res) {

		if (res.statusCode != 200) {
			console.error('Platform "%s_%s-%s" is not supported', getNodeBuildVersion(), platform, process.arch);
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
			console.log('NODE %s IS NOT SUPPORTED', process.version);
		}
	}
});

function getNodeBuildVersion () {
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
