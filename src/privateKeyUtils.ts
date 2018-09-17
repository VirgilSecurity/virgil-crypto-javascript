import { VirgilPrivateKey } from "./VirgilPrivateKey";

const privateKeys = new WeakMap();
const setValue = WeakMap.prototype.set;
const getValue = WeakMap.prototype.get;
const hasValue = WeakMap.prototype.has;

/**
 * Gets the private key bytes of the given private key object from internal store.
 * @param {VirgilPrivateKey} privateKey - Private key object.
 * @returns {Buffer} - Private key bytes.
 *
 * @hidden
 */
export function getPrivateKeyBytes(privateKey: VirgilPrivateKey): Buffer {
	return getValue.call(privateKeys, privateKey);
}

/**
 * Saves the private key bytes corresponding to the given private key object into
 * internal buffer.
 *
 * @param {VirgilPrivateKey} privateKey - Private key object.
 * @param {Buffer} bytes - Private key bytes.
 *
 * @hidden
 */
export function setPrivateKeyBytes(privateKey: VirgilPrivateKey, bytes: Buffer) {
	setValue.call(privateKeys, privateKey, bytes);
}

/**
 * Checks if the private key bytes corresponding to the given private key
 * object exist in the internal buffer.
 *
 * @hidden
 *
 * @param { VirgilPrivateKey } privateKey - Private key object.
 *
 * @returns {boolean}
 */
export function hasPrivateKeyBytes(privateKey: VirgilPrivateKey): boolean {
	return hasValue.call(privateKeys, privateKey);
}
