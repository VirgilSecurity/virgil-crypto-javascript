/// <reference types="node" />
import { HashAlgorithm } from 'virgil-crypto-utils';
/**
 * Produces a hash of given data
 *
 * @param {Buffer} data - Data to hash
 * @param {string} [algorithm] - Hash algorithm to use. Default is SHA256
 *
 * @returns {Buffer}
 * */
export declare function hash(data: Buffer, algorithm?: HashAlgorithm): any;
