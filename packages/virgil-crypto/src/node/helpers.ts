import { createNativeTypeWrapper } from '../common';
import lib from '../../virgil_crypto_node.node';

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

const toString = Object.prototype.toString;

function isVirgilByteArray(obj: any) {
	if (obj == null) {
		return false;
	}

	const tag = toString.call(obj);
	return tag === '[object _exports_VirgilByteArray]' || tag === '[object VirgilByteArray]';
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
