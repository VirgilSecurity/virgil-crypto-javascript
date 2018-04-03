import { createNativeTypeWrapper } from '../common';
import { lib } from './asmjs';

export function isBuffer (obj: any) {
	return Buffer.isBuffer(obj);
}

function bufferToVirgilByteArray(buffer: Buffer) {
	return lib.VirgilByteArray.fromUint8Array(buffer);
}

function isVirgilByteArray(obj: any) {
	return obj != null && obj.constructor === lib.VirgilByteArray;
}

export function virgilByteArrayToBuffer(byteArray: any) {
	const size = byteArray.size();
	const buffer = new Buffer(size);

	for (let i = 0; i < size; ++i) {
		buffer[i] = byteArray.get(i);
	}

	return buffer;
}

export const wrapper = createNativeTypeWrapper({
	isBuffer,
	bufferToVirgilByteArray,
	isVirgilByteArray,
	virgilByteArrayToBuffer
});
