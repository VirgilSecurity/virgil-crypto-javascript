const resolve = require('rollup-plugin-node-resolve');
const commonjs = require('rollup-plugin-commonjs');
const typescript = require('rollup-plugin-typescript2');
const inject = require('rollup-plugin-inject');
const replace = require('rollup-plugin-replace');
const builtins = require('rollup-plugin-node-builtins');
const globals = require('rollup-plugin-node-globals');
const { uglify } = require('rollup-plugin-uglify');
const globalScript = require('./rollup-plugin-global-script');
const resolveCryptoLib = require('./rollup-plugin-resolve-crypto-lib');
const bundleTypes = require('./bundle-types');

const BROWSER_ONLY_PLUGINS = [
	inject({
		include: '**/*.ts',
		exclude: 'node_modules/**',
		modules: {
			Buffer: [ 'buffer-es6', 'Buffer' ]
		}
	})
];

function getRollupPlugins(bundleType) {
	const isBrowser = bundleType !== bundleTypes.NODE;
	const isProd = bundleType === bundleTypes.BROWSER_PROD;

	return [
		resolveCryptoLib(isBrowser),

		globalScript('src/lib/virgil_crypto_asmjs.js'),

		globalScript('src/lib/virgil_crypto_pythia_asmjs.js'),

		resolve({
			browser: isBrowser,
			jsnext: true,
			extensions: [ '.ts', '.js' ],
			preferBuiltins: !isBrowser
		}),

		globals(),
		builtins(),

		commonjs({
			ignoreGlobal: true
		}),

		typescript({
			useTsconfigDeclarationDir: true,
			tsconfigOverride: {
				compilerOptions: {
					module: 'es2015'
				}
			}
		}),

		replace({ 'process.browser': JSON.stringify(isBrowser) }),

		...(isBrowser ? BROWSER_ONLY_PLUGINS : []),

		...(isProd ? [ uglify() ] : [])
	];
}

module.exports = getRollupPlugins;
