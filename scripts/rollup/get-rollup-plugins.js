const resolve = require('rollup-plugin-node-resolve');
const typescript = require('rollup-plugin-typescript2');
const inject = require('rollup-plugin-inject');
const replace = require('rollup-plugin-replace');
const globals = require('rollup-plugin-node-globals');
const { uglify } = require('rollup-plugin-uglify');
const globalScript = require('./rollup-plugin-global-script');
const resolveCryptoLib = require('./rollup-plugin-resolve-crypto-lib');
const bundleTypes = require('./bundle-types');

function getRollupPlugins(bundleType) {
	const isBrowser = bundleType !== bundleTypes.NODE;
	const isProd = bundleType === bundleTypes.BROWSER_PROD;

	return [
		resolveCryptoLib(isBrowser),

		globalScript('src/lib/virgil_crypto_asmjs.js'),

		globalScript('src/lib/virgil_crypto_pythia_asmjs.js'),

		resolve({
			browser: isBrowser,
			extensions: [ '.ts', '.js' ],
		}),

		typescript({
			useTsconfigDeclarationDir: true,
			typescript: require('typescript')
		}),

		replace({ 'process.browser': JSON.stringify(isBrowser) }),

		isBrowser && globals(),
		isBrowser && inject({
			include: '**/*.ts',
			exclude: 'node_modules/**',
			modules: {
				Buffer: [ 'buffer-es6', 'Buffer' ]
			}
		}),

		isProd && uglify()
	];
}

module.exports = getRollupPlugins;
