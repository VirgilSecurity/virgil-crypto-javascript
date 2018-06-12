/**
 * String decoding utilities.
 */
export const encoding = {
	/**
	 * Decodes the base64-encoded string and returns `Buffer`.
	 * @param {string} str - The string to decode.
	 * @returns {Buffer}
	 */
	base64ToBytes (str: string) {
		return Buffer.from(str, 'base64');
	},

	/**
	 * Decodes the hex string and returns `Buffer`.
	 * @param {string} str - The string to decode.
	 * @returns {Buffer}
	 */
	hexToBytes (str: string) {
		return Buffer.from(str, 'hex');
	},

	/**
	 * Decodes the utf8 string and returns `Buffer`.
	 * @param {string} str - The string to decode.
	 * @returns {Buffer}
	 */
	stringToBytes (str: string) {
		return Buffer.from(str, 'utf8');
	}
};
