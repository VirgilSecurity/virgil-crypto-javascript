const path = require('path');

const nodeCryptoModuleId = path.resolve('src/lib/node');
const nodePythiaModuleId = path.resolve('src/lib/pythia-node');
const browserCryptoModuleId = path.resolve('src/lib/browser');
const browserPythiaModuleId = path.resolve('src/lib/pythia-browser');

function resolveCryptoLib (isBrowser) {
	return {
		name: 'resolve-crypto-lib',
		resolveId (importee, importer) {
			if (importer) {
				const resolved = path.resolve(path.dirname(importer), importee);
				if (resolved === nodeCryptoModuleId) {
					let actualModuleId;
					if (process.env.PYTHIA) {
						if (isBrowser) {
							actualModuleId = browserPythiaModuleId;
						} else {
							actualModuleId = nodePythiaModuleId;
						}
					} else if (isBrowser) {
						actualModuleId = browserCryptoModuleId;
					} else {
						actualModuleId = nodeCryptoModuleId;
					}
					return actualModuleId + '.ts';
				}
			}
		}
	}
}

module.exports = resolveCryptoLib;
