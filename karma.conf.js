const bundleTypes = require('./scripts/rollup/bundle-types');
const getRollupPlugins = require('./scripts/rollup/get-rollup-plugins');

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
		browserNoActivityTimeout: 180 * 1000,

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
