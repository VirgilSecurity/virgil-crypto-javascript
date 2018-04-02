export function toArray(val: any) {
	return Array.isArray(val)
		? val
		: val === undefined ? val : [ val ];
}
