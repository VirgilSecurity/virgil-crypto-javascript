const builtinModules = require('builtin-modules');
const { promisify } = require('util');
const rimraf = promisify(require('rimraf'));
const mkdirp = promisify(require('mkdirp'));
const path = require('path');
const { rollup } = require('rollup');
const bundleTypes = require('./bundle-types');
const getRollupPlugins = require('./get-rollup-plugins');

const NODE = bundleTypes.NODE;
const BROWSER = bundleTypes.BROWSER;
const BROWSER_PROD = bundleTypes.BROWSER_PROD;

const virgilCrypto = {
	path: '.',
	entry: 'src/index.ts',
	filename: 'virgil-crypto',
	global: 'VirgilCrypto',
	external: [ path.resolve('./virgil_crypto_node.node') ],
	bundleTypes: [ NODE, BROWSER, BROWSER_PROD ]
};

const virgilPythiaCrypto = {
	path: '.',
	entry: 'src/pythia.ts',
	filename: 'virgil-crypto-pythia',
	global: 'VirgilCryptoPythia',
	external: [ path.resolve('./virgil_crypto_node.node') ],
	bundleTypes: [ NODE, BROWSER, BROWSER_PROD ]
};

function createBundle(bundle) {
	return Promise.all(bundle.bundleTypes.map(bundleType => {
		const entry = bundle.entry;
		return rollup({
			input: path.resolve(bundle.path, entry),
			external: [ ...builtinModules, ...(bundle.external || []) ],
			plugins: getRollupPlugins(bundleType)
		}).then(output => {
			const formats = getOutputFormatsFromBundleType(bundleType);
			return Promise.all(formats.map(format => {
				const file = getOutpupFilenameFormBundleType(bundle.filename, format, bundleType);
				return output.write({
					format: format,
					name: bundle.global,
					file: path.resolve(bundle.path, file)
				}).then(() => {
					console.log('  \u2713' + ' wrote ' +
						path.basename(path.resolve(bundle.path)) + '/' + file);
				})
			}))
		});
	}));
}

function getOutpupFilenameFormBundleType(filename, format, bundleType) {
	switch (bundleType) {
		case NODE:
			return `dist/${filename}.${format}.js`;
		case BROWSER:
			return `dist/${filename}.browser.${format}.js`;
		case BROWSER_PROD:
			return `dist/${filename}.browser.${format}.min.js`;
	}
}

function getOutputFormatsFromBundleType(bundleType) {
	switch (bundleType) {
		case NODE:
			return [ 'cjs', 'es' ];
		case BROWSER:
			return [ 'umd', 'cjs', 'es' ];
		case BROWSER_PROD:
			return [ 'umd' ];
	}
}

function bundleVirgilCrypto() {
	return createBundle(virgilCrypto);
}

function bundleVirgilPythiaCrypto() {
	return createBundle(virgilPythiaCrypto);
}

function build() {
	return Promise.resolve()
		.then(() => rimraf(path.resolve('dist')))
		.then(() => mkdirp(path.resolve('dist')))
		.then(bundleVirgilCrypto)
		.then(bundleVirgilPythiaCrypto)
		.catch(e => console.error(e));
}

if (require.main === module) {
	build();
} else {
	module.exports = build;
}
