export function toArray<T>(val?: T|T[]): T[]|undefined|null {
	return val == null
		? val
		: isArray(val) ? val : [ val ];
}

function isArray<T>(obj: T|T[]): obj is T[] {
	return Array.isArray(obj);
}
