import isBuffer from 'is-buffer';
import VirgilCrypto from './crypto-module';
import createWrapper from '../../lib/wrapper';

export function bufferToByteArray(buffer) {
	// Buffers are backed by Uint8Array
	return VirgilCrypto.VirgilByteArray.fromUint8Array(buffer);
}

/**
 * Converts the given {VirgilByteArray} to {Buffer} and releases the
 * memory held by the array.
 *
 * @param {VirgilByteArray} byteArray - Byte array to transform.
 */
export function convertToBufferAndRelease(byteArray) {
	const buf = byteArrayToBuffer(byteArray);
	byteArray.delete();
	return buf;
}

export function byteArrayToBuffer(byteArray) {
	let size = byteArray.size();
	let buffer = new Buffer(size);

	for (let i = 0; i < size; ++i) {
		buffer[i] = byteArray.get(i);
	}

	return buffer;
}

export function stringToByteArray(string) {
	return bufferToByteArray(new Buffer(string, 'utf8'));
}

export function toByteArray(data) {
	switch (true) {
		case Buffer.isBuffer(data):
			return bufferToByteArray(data);
		case typeof data === 'string':
			return stringToByteArray(data);
		default:
			throw new Error(`Can't convert ${typeof data} to ByteArray.`);
	}
}

export function toBase64(data) {
	return data.toString('base64');
}

export function base64ToBuffer(data) {
	return new Buffer(data, 'base64');
}

export function isVirgilByteArray(obj) {
	return obj
		&& obj.constructor
		&& obj.constructor.name === 'VirgilByteArray';
}

export { isBuffer as isBuffer };

export function byteArraysEqual(a, b) {
	const aLen = a.size();
	const bLen = b.size();

	if (aLen !== bLen) {
		return false;
	}

	for (let i = 0; i < aLen; i++) {
		if (a.get(i) !== b.get(i)) {
			return false;
		}
	}

	return true;
}

export function isObjectLike(value) {
	return !!value && typeof value == 'object';
}

export const wrapper = createWrapper({
	toByteArray,
	byteArrayToBuffer,
	isVirgilByteArray,
	isBuffer
});
