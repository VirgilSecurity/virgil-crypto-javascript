const resolve = require('rollup-plugin-node-resolve');
const commonjs = require('rollup-plugin-commonjs');
const typescript = require('rollup-plugin-typescript2');
const inject = require('rollup-plugin-inject');
const replace = require('rollup-plugin-replace');
const globals = require('rollup-plugin-node-globals');
const builtinModules = require('builtin-modules');
const path = require('path');

const NODE_ENTRY_PATH = path.resolve('src/index.ts');
const BROWSER_ENTRY_PATH = path.resolve('src/browser.ts');

module.exports = function (config) {
	config.set({
		frameworks: [ 'mocha', 'chai' ],
		autoWatch: false,
		browsers: [ 'Chrome' ],
		files: [ { pattern: 'src/**/*.test.ts', watched: false } ],
		mime: { 'text/x-typescript': ['ts'] },
		logLevel: config.LOG_INFO,
		singleRun: true,

		preprocessors: {
			'src/**/*.ts': [ 'rollup' ]
		},

		rollupPreprocessor: {
			plugins: [
				{
					resolveId(importee, importer) {
						if (importer) {
							const filename = path.resolve(path.dirname(importer), importee) + '.ts';
							if (filename === NODE_ENTRY_PATH) {
								return BROWSER_ENTRY_PATH;
							}
						}
					}
				},
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

				resolve({
					browser: true,
					jsnext: true
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
