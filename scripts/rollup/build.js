const resolve = require('rollup-plugin-node-resolve');
const commonjs = require('rollup-plugin-commonjs');
const typescript = require('rollup-plugin-typescript2');
const inject = require('rollup-plugin-inject');
const replace = require('rollup-plugin-replace');
const globals = require('rollup-plugin-node-globals');
const builtinModules = require('builtin-modules');
const { promisify } = require('util');
const rimraf = promisify(require('rimraf'));
const mkdirp = promisify(require('mkdirp'));
const path = require('path');
const { rollup } = require('rollup');

const BROWSER_ONLY_PLUGINS = [
	inject({
		include: '**/*.ts',
		exclude: 'node_modules/**',
		modules: {
			Buffer: [ 'buffer-es6', 'Buffer' ]
		}
	}),

	globals({
		exclude: [ '**/virgil_crypto_asmjs.js', '**/virgil_crypto_webasm.js' ]
	})
];

const NODE = false;
const BROWSER = true;

const bundles = [
	{
		path: 'packages/virgil-crypto-utils',
		filename: 'virgil-crypto-utils',
		global: 'VirgilCryptoUtils',
		versions: [ BROWSER, NODE ]
	},
	{
		path: 'packages/virgil-crypto-browser',
		filename: 'virgil-crypto-browser',
		global: 'virgilCryptoFactory',
		versions: [ BROWSER ],
		browserOnly: true
	},
	{
		path: 'packages/virgil-crypto-node',
		filename: 'virgil-crypto-node',
		global: 'VirgilCrypto',
		external: [ path.resolve('packages/virgil-crypto-node/virgil_crypto_node.node') ],
		versions: [ NODE ]
	}
];

const virgilCrypto = {
	path: 'packages/virgil-crypto',
	filename: 'virgil-crypto',
	global: 'virgilCrypto',
	external: [ 'virgil-crypto-node' ],
	versions: [ NODE, BROWSER ]
};

function runSequence(factories) {
	return factories.reduce((chain, f) => chain.then(f), Promise.resolve());
}

function createBundle(bundle) {
	const pkg = require(path.resolve(bundle.path, 'package.json'));

	return Promise.resolve()
		.then(() => rimraf(path.resolve(bundle.path, 'dist')))
		.then(() => mkdirp(path.resolve(bundle.path, 'dist')))
		.then(() => {
			return runSequence(bundle.versions.map(isBrowser => () => {
				const browserEntry = typeof pkg.browser === 'object' && pkg.browser['./src/index.ts']
					? pkg.browser['./src/index.ts']
					: 'src/index.ts';

				const entry = isBrowser ? browserEntry : 'src/index.ts';
				return rollup({
					input: path.resolve(bundle.path, entry),
					external: [ ...builtinModules, ...(bundle.external || []) ],
					plugins: [
						typescript({
							useTsconfigDeclarationDir: true,
							tsconfigOverride: {
								compilerOptions: {
									declarationDir: bundle.path + '/dist/types'
								},
								include: [ bundle.path + '/src' ]
							}
						}),

						replace({ 'process.browser': JSON.stringify(isBrowser) }),

						...(isBrowser ? BROWSER_ONLY_PLUGINS : []),

						resolve({
							browser: isBrowser,
							jsnext: true
						}),

						commonjs({
							ignore: [ ...builtinModules, 'virgil-crypto-browser' ]
						})
					]
				}).then(output => {
					const formats = [ ...(isBrowser ? ['umd'] : []), 'cjs', 'es' ];
					return Promise.all(formats.map(format => {
						const suffix = isBrowser && !bundle.browserOnly ? '.browser' : '';
						const file = `dist/${bundle.filename}${suffix}.${format}.js`;
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
		});
}

function bundleVirgilCrypto() {
	return createBundle(virgilCrypto);
}

function build() {
	return Promise.all(bundles.map(createBundle))
		.then(() => {
			console.log('Creating main bundle...');
			return bundleVirgilCrypto();
		})
		.then(() => console.log('All done!'))
		.catch(e => console.error(e));
}

if (require.main === module) {
	build();
} else {
	module.exports = build;
}
