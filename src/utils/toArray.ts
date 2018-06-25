/**
 * Converts `val` to an array. If `val` is already an array, it is returned as is.
 * @hidden
 * @param {T[] | T} val - Value to convert.
 * @returns {T[]} Converted array
 */
export function toArray<T>(val?: T|T[]): T[] {
	return val == null
		? []
		: Array.isArray(val) ? val : [ val ];
}
