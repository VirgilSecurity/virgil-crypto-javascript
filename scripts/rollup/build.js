const builtinModules = require('builtin-modules');
const path = require('path');
const { rollup } = require('rollup');
const bundleTypes = require('./bundle-types');
const getRollupPlugins = require('./get-rollup-plugins');

const NODE = bundleTypes.NODE;
const BROWSER = bundleTypes.BROWSER;
const BROWSER_PROD = bundleTypes.BROWSER_PROD;

const virgilCrypto = {
	path: '.',
	entry: Boolean(process.env.PYTHIA) ? 'src/pythia.ts' : 'src/index.ts',
	filename: Boolean(process.env.PYTHIA) ? 'virgil-crypto-pythia' : 'virgil-crypto',
	global: 'VirgilCrypto',
	external: [ path.resolve('./virgil_crypto_node.node') ],
	bundleTypes: [ NODE, BROWSER, BROWSER_PROD ]
};

function createBundle(bundle) {
	return Promise.all(bundle.bundleTypes.map(bundleType => {
		const entry = bundle.entry;
		return rollup({
			input: path.resolve(bundle.path, entry),
			external: [ ...builtinModules, ...(bundle.external || []) ],
			plugins: getRollupPlugins(bundleType),
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

function build() {
	return Promise.resolve()
		.then(() => createBundle(virgilCrypto))
		.catch(e => console.error(e));
}

if (require.main === module) {
	build();
} else {
	module.exports = build;
}
