/**
 * Converts `val` to an array. If `val` is already an array, it is returned as is.
 * @hidden
 * @param {T[] | T} val - Value to convert.
 * @returns {T[]} Converted array
 */
export function toArray<T>(val?: T|T[]): T[] {
	return val == null
		? []
		: isArray(val) ? val : [ val ];
}

/**
 * Checks if `val` is an array.
 * @hidden
 * @param {T[] | T} val
 * @returns {boolean}
 */
function isArray<T>(val: T|T[]): val is T[] {
	return Array.isArray(val);
}
