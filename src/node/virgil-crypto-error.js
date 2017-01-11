'use strict';

var inherits = require('util').inherits;

function VirgilCryptoError(message, extra) {
	if (Error.captureStackTrace) {
		Error.captureStackTrace(this, this.constructor);
	} else {
		var stack = new Error().stack;
		if (stack) {
			this.stack = stack;
		}
	}

	this.name = this.constructor.name;
	this.message = message;
	this.extra = extra;
}

inherits(VirgilCryptoError, Error);

module.exports = VirgilCryptoError;
