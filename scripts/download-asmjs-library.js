var fs = require('fs');
var path = require('path');
var del = require('del');
var request = require('request');
var targz = require('tar.gz');
var recursiveReadDir = require('recursive-readdir');

var downloadPath = path.resolve(path.join(__dirname, '../temp'));
var downloadUrl = 'https://cdn.virgilsecurity.com/virgil-crypto/asmjs/virgil-crypto-1.2.0-asmjs.tar.gz';
var libPath = path.resolve(path.join(__dirname, '../src/lib/virgil-emscripten.js'));

request
	.get(downloadUrl)
	.on('response', function(res) {
		if (res.statusCode != 200) {
			abortWithError(res.statusMessage);
		}
	})
	.on('error', abortWithError)
	.on('end', function() {
		if (fs.existsSync(downloadPath)) {
			console.log('The Virgil Crypto asmjs build successfully downloaded.\n\n');
			console.log('Updating asmjs library...\n\n');

			recursiveReadDir(downloadPath, function(err, fileNames) {
				if (err) {
					abortWithError();
				} else {
					var file = fileNames.find(function(fileName) {
						return fileName.match(/^.*\.js$/i);
					});

					fs.writeFileSync(libPath, fs.readFileSync(file));

					console.log('The asmjs library updated successfully...\n\n');

					del(downloadPath);
				}
			});
		} else {
			abortWithError();
		}
	})
	.pipe(targz().createWriteStream(downloadPath));

function abortWithError(error) {
	console.log('Something goes wrong, the Virgil Crypto asmjs build is not downloaded yet.');

	if (error) {
		console.log(error);
	}

	process.exit(-1);
}
