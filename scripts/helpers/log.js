const Colors = {
	RED: '\x1b[31m',
	CYAN: '\x1b[36m',
	LIGHT_GREEN: '\x1b[92m',
	RESET: '\x1b[0m'
};

module.exports = {
	error(err) {
		console.log(Colors.RED + 'virgil-crypto: ' + err.toString() + Colors.RESET);
	},

	info(message) {
		console.log(Colors.CYAN + 'virgil-crypto: ' + Colors.RESET + message);
	},

	success(message) {
		console.log(Colors.LIGHT_GREEN + 'virgil-crypto: ' + Colors.RESET + message);
	}
};
