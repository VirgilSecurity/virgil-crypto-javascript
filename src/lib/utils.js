'use strict';

var isBuffer = require('is-buffer');

module.exports = {
	isBuffer: isBuffer,

	toArray: function toArray(obj) {
		return Array.isArray(obj) ? obj : (obj ? [obj] : obj);
	},

	isObjectLike: function isObjectLike(value) {
		return !!value && typeof value == 'object';
	},

	find: function find(array, predicate, context) {
		if (array == null) {
			throw new TypeError('Array to search is null or undefined');
		}

		if (typeof Array.prototype.find === 'function') {
			return Array.prototype.find.call(array, predicate, context);
		}

		if (typeof predicate !== 'function') {
			throw new TypeError(predicate + ' is not a function');
		}

		context = context || this;
		var list = Object(array);
		var length = list.length >>> 0;
		var value;

		for (var i = 0; i < length; i++) {
			value = list[i];
			if (predicate.call(context, value, i, list)) {
				return value;
			}
		}

		return undefined;
	}
};
