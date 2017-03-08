var isBuffer = require('is-buffer');

module.exports = function createWrapper (utils) {
	return {
		wrapMethods: wrapMethods,
		wrapFunction: wrapFunction
	};

	// Add type conversions to class methods
	function wrapMethods (proto) {
		Object.keys(proto)
			.filter(function (prop) {
				return typeof proto[prop] === 'function';
			})
			.forEach(function (method) {
				proto[method] = wrapFunction(proto[method]);
			});
	}

	// Wrap function with type conversions
	function wrapFunction (func) {
		return function wrappedFunction () {
			var args = Array.prototype.slice.apply(arguments);

			for (var i = 0; i < args.length; ++i) {
				// Convert strings and Buffer to VirgilByteArray
				if (typeof args[i] === 'string' || isBuffer(args[i])) {
					args[i] = utils.toByteArray(args[i]);
				}
			}

			var result = func.apply(this, args);

			// ByteArray
			if (utils.isVirgilByteArray(result)) {
				return utils.byteArrayToBuffer(result);
			}

			return result;
		}
	}
};
