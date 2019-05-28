const bundleTypes = require('./scripts/rollup/bundle-types');
const getRollupPlugins = require('./scripts/rollup/get-rollup-plugins');

const entry = process.env.TEST_ASMJS_MEMORY_MGMT ? 'src/tests/memory/index.ts' : 'src/tests/index.ts';

module.exports = function (config) {
	config.set({
		frameworks: [ 'mocha', 'chai' ],
		autoWatch: false,
		browsers: [ 'ChromeHeadless' ],
		files: [ { pattern: entry, watched: false } ],
		colors: true,
		reporters: [ 'progress' ],
		mime: { 'text/x-typescript': ['ts'] },
		logLevel: config.LOG_INFO,
		singleRun: true,
		browserDisconnectTolerance: 2,
		browserNoActivityTimeout: 200 * 1000,

		preprocessors: {
			'src/**/*.ts': [ 'rollup' ]
		},

		rollupPreprocessor: {
			plugins: getRollupPlugins(bundleTypes.BROWSER),

			output: {
				format: 'iife',
				name: 'VirgilCrypto'
			}
		}
	});
};
