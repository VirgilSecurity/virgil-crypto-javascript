/// <reference path="./declarations.d.ts" />
import { createNativeFunctionWrapper } from 'virgil-crypto-utils';
import lib from '../virgil_crypto_node.node';

export function isBuffer (obj: any) {
	return Buffer.isBuffer(obj);
}

function bufferToVirgilByteArray(buffer: Buffer) {
	const array = new lib.VirgilByteArray(buffer.byteLength);

	for (let i = 0; i < buffer.length; ++i) {
		array.set(i, buffer[i]);
	}

	return array;
}

const EXPORTED_BYTE_ARRAY = lib.VirgilByteArrayUtils.stringToBytes('');

function isVirgilByteArray(obj: any) {
	return obj != null &&
		obj.constructor === lib.VirgilByteArray ||
		obj.constructor === EXPORTED_BYTE_ARRAY.constructor;
}

export function virgilByteArrayToBuffer(byteArray: any) {
	const size = byteArray.size();
	const buffer = new Buffer(size);

	for (let i = 0; i < size; ++i) {
		buffer[i] = byteArray.get(i);
	}

	return buffer;
}

export const wrapFunction = createNativeFunctionWrapper({
	isBuffer,
	bufferToVirgilByteArray,
	isVirgilByteArray,
	virgilByteArrayToBuffer
});
