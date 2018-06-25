/**
 * @hidden
 */
export type StringEncoding = 'utf8'|'base64'|'hex';

/**
 * Attempts to convert the given `value` to Buffer. Throws a `TypeError` if the
 * `value` cannot be converted.
 *
 * @hidden
 *
 * @param {string | Buffer | ArrayBuffer} value - The value to convert.
 *
 * If `value` is Buffer, it is used as is, without copying the underlying memory.
 *
 * If `value` is ArrayBuffer, creates a view if the ArrayBuffer without copying
 * the underlying memory.
 *
 * @param {string} encoding - If `value` is a string, specifies its encoding,
 * otherwise is ignored.
 * @param {string} [label] - The name of the argument to include in error message
 * in case when the value cannot be converted to Buffer.
 * @returns {Buffer}
 */
export function anyToBuffer (
	value: string|Buffer|ArrayBuffer, encoding: StringEncoding, label: string = 'argument'
): Buffer {
	if (Buffer.isBuffer(value)) {
		return value;
	}

	if (typeof value === 'string') {
		return Buffer.from(value, encoding);
	}

	if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
		return Buffer.from(value);
	}

	throw new TypeError(
		`Expected \`${label}\` to be a string, Buffer or ArrayBuffer, got ${typeof value}.`
	);
}
