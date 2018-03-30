/// <reference path="./declarations.d.ts" />

export interface WrapperUtils {
	isBuffer (obj: any): boolean;
	bufferToVirgilByteArray (buf: Buffer): any;
	isVirgilByteArray (obj: any): boolean;
	virgilByteArrayToBuffer (arr: any): Buffer;
}

const apply = Function.prototype.apply;

export function createNativeFunctionWrapper (utils: WrapperUtils) {

	if (process.browser) {
		return wrapNativeFunctionBrowser;
	}

	return wrapNativeFunctionNode;

	function wrapNativeFunctionBrowser(fn: Function, target: any) {
		return function (...args: any[]) {
			const allocations: any[] = [];
			const transformedArgs = args.map(arg => {
				if (utils.isBuffer(arg)) {
					const arr = utils.bufferToVirgilByteArray(arg);
					allocations.push(arr);
					return arr;
				}

				return arg;
			});

			let result;
			try {
				result = Function.prototype.apply.call(fn, target, transformedArgs);
				if (utils.isVirgilByteArray(result)) {
					allocations.push(result);
					result = utils.virgilByteArrayToBuffer(result);
				}

				return result;
			} finally {
				allocations.forEach(arr => arr.delete());
			}
		}
	}

	function wrapNativeFunctionNode(fn: Function, target: any) {
		return function (...args: any[]) {
			const transformedArgs = args.map(
				arg => utils.isBuffer(arg) ? utils.bufferToVirgilByteArray(arg) : arg
			);

			let result = apply.call(fn, target, transformedArgs);
			if (utils.isVirgilByteArray(result)) {
				result = utils.virgilByteArrayToBuffer(result);
			}

			return result;
		}
	}
}
