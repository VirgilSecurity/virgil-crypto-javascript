const resolve = require('rollup-plugin-node-resolve');
const commonjs = require('rollup-plugin-commonjs');
const typescript = require('rollup-plugin-typescript2');
const inject = require('rollup-plugin-inject');
const replace = require('rollup-plugin-replace');
const globals = require('rollup-plugin-node-globals');
const builtinModules = require('builtin-modules');

module.exports = function (config) {
	config.set({
		frameworks: [ 'mocha', 'chai' ],
		autoWatch: false,
		browsers: [ 'ChromeHeadless' ],
		files: [ { pattern: 'src/tests/index.ts', watched: false } ],
		colors: true,
		reporters: [ 'progress' ],
		mime: { 'text/x-typescript': ['ts'] },
		logLevel: config.LOG_INFO,
		singleRun: true,
		browserNoActivityTimeout: 120 * 1000,

		preprocessors: {
			'src/**/*.ts': [ 'rollup' ]
		},

		rollupPreprocessor: {
			plugins: [
				resolve({
					browser: true,
					jsnext: true,
					extensions: [ '.ts', '.js' ],
					preferBuiltins: false,
					include: [ 'src/**' ]
				}),
				typescript({
					tsconfigOverride: {
						compilerOptions: {
							module: 'es2015'
						}
					}
				}),

				replace({ 'process.browser': JSON.stringify(true) }),

				inject({
					include: '**/*.ts',
					exclude: 'node_modules/**',
					modules: {
						Buffer: [ 'buffer-es6', 'Buffer' ]
					}
				}),

				globals({
					exclude: [ '**/virgil_crypto_asmjs.js' ]
				}),

				commonjs({
					ignore: builtinModules,
					namedExports: { chai: [ 'assert', 'expect', 'should' ] }
				})
			],

			output: {
				format: 'iife',
				name: 'VirgilCrypto'
			}
		}
	});
};
