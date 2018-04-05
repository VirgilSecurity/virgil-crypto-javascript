const { minify } = require('uglify-es');
const { createFilter } = require('rollup-pluginutils');

function myUglify(userOptions = {}) {
	const { include, exclude, ...rest } = userOptions;
	const minifierOptions = Object.assign({ sourceMap: false }, rest);
	const filter = createFilter(include, exclude);

	return {
		name: "myUglify",

		transformBundle(code, id) {
			if (!filter(id)) {
				return;
			}

			const result = minify(code, minifierOptions);
			if (result.error) {
				throw result.error;
			}
			return result;
		}
	};
}

module.exports = myUglify;
