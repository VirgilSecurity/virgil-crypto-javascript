import lib from '../virgil_crypto_node.node';

/*! *****************************************************************************
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache Version 2.0 License for specific language governing permissions
and limitations under the License.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = Object.setPrototypeOf ||
    ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
    function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var VirgilCryptoError = /** @class */ (function (_super) {
    __extends(VirgilCryptoError, _super);
    function VirgilCryptoError(message, code, name) {
        var _this = _super.call(this, message) || this;
        _this.name = 'VirgilCryptoError';
        Object.setPrototypeOf(_this, VirgilCryptoError.prototype);
        _this.code = code;
        if (name !== undefined) {
            _this.name = name;
        }
        return _this;
    }
    VirgilCryptoError.prototype.toString = function () {
        return this.name + ": " + (this.code !== undefined ? this.code : 'UNKNOWN') + ": " + this.message + ".";
    };
    return VirgilCryptoError;
}(Error));
function errorFromNativeError(err) {
    if (!(err instanceof Error)) {
        return err;
    }
    // Error messages from native virgil-crypto consist of two
    // lines: one from VirgilCrypto itself, another one from
    // mbed-tls. We are only interested in the former since it
    // contains a friendlier message.
    var virgilCryptoMessage = err.message.split(/\r?\n/)[0];
    if (!virgilCryptoMessage) {
        return err;
    }
    // Expected message format is as follows:
    // "Module: virgil/crypto. Error code: {code}. {name}. {message}."
    var parts = virgilCryptoMessage.split(/\s*\.\s*/);
    if (parts.length === 1) {
        // Error message didn't match what we expected.
        return err;
    }
    var code = parts[1], name = parts[2], message = parts[3];
    return new VirgilCryptoError(message, code, name);
}

var HashAlgorithm;
(function (HashAlgorithm) {
    HashAlgorithm["MD5"] = "MD5";
    HashAlgorithm["SHA1"] = "SHA1";
    HashAlgorithm["SHA224"] = "SHA224";
    HashAlgorithm["SHA256"] = "SHA256";
    HashAlgorithm["SHA384"] = "SHA384";
    HashAlgorithm["SHA512"] = "SHA512";
})(HashAlgorithm || (HashAlgorithm = {}));

var KeyPairType;
(function (KeyPairType) {
    KeyPairType["Default"] = "FAST_EC_ED25519";
    KeyPairType["RSA_2048"] = "RSA_2048";
    KeyPairType["RSA_3072"] = "RSA_3072";
    KeyPairType["RSA_4096"] = "RSA_4096";
    KeyPairType["RSA_8192"] = "RSA_8192";
    KeyPairType["EC_SECP256R1"] = "EC_SECP256R1";
    KeyPairType["EC_SECP384R1"] = "EC_SECP384R1";
    KeyPairType["EC_SECP521R1"] = "EC_SECP521R1";
    KeyPairType["EC_BP256R1"] = "EC_BP256R1";
    KeyPairType["EC_BP384R1"] = "EC_BP384R1";
    KeyPairType["EC_BP512R1"] = "EC_BP512R1";
    KeyPairType["EC_SECP256K1"] = "EC_SECP256K1";
    KeyPairType["EC_CURVE25519"] = "EC_CURVE25519";
    KeyPairType["FAST_EC_X25519"] = "FAST_EC_X25519";
    KeyPairType["FAST_EC_ED25519"] = "FAST_EC_ED25519";
})(KeyPairType || (KeyPairType = {}));

/// <reference path="./declarations.d.ts" />
var apply = Function.prototype.apply;
function createNativeFunctionWrapper(utils) {
    return wrapNativeFunctionNode;
    function wrapNativeFunctionNode(fn, target) {
        return function () {
            var args = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                args[_i] = arguments[_i];
            }
            var transformedArgs = args.map(function (arg) { return utils.isBuffer(arg) ? utils.bufferToVirgilByteArray(arg) : arg; });
            var result = apply.call(fn, target, transformedArgs);
            if (utils.isVirgilByteArray(result)) {
                result = utils.virgilByteArrayToBuffer(result);
            }
            return result;
        };
    }
}

/// <reference path="./declarations.d.ts" />
function isBuffer(obj) {
    return Buffer.isBuffer(obj);
}
function bufferToVirgilByteArray(buffer) {
    var array = new lib.VirgilByteArray(buffer.byteLength);
    for (var i = 0; i < buffer.length; ++i) {
        array.set(i, buffer[i]);
    }
    return array;
}
var EXPORTED_BYTE_ARRAY = lib.VirgilByteArrayUtils.stringToBytes('');
function isVirgilByteArray(obj) {
    return obj != null &&
        obj.constructor === lib.VirgilByteArray ||
        obj.constructor === EXPORTED_BYTE_ARRAY.constructor;
}
function virgilByteArrayToBuffer(byteArray) {
    var size = byteArray.size();
    var buffer = new Buffer(size);
    for (var i = 0; i < size; ++i) {
        buffer[i] = byteArray.get(i);
    }
    return buffer;
}
var wrapFunction = createNativeFunctionWrapper({
    isBuffer: isBuffer,
    bufferToVirgilByteArray: bufferToVirgilByteArray,
    isVirgilByteArray: isVirgilByteArray,
    virgilByteArrayToBuffer: virgilByteArrayToBuffer
});

var generate = wrapFunction(lib.VirgilKeyPair.generate, lib.VirgilKeyPair);
var generateRecommended = wrapFunction(lib.VirgilKeyPair.generateRecommended, lib.VirgilKeyPair);
/**
 * Generate the key pair - public and private keys
 *
 * @param {Object} [options={}] - Keypair options.
 * @param {Buffer} [options.password] - Private key password (Optional).
 * @param {string} [options.type=] - Keys type identifier (Optional).
 * 		If provided must be one of KeyPairType values.
 * @returns {{publicKey: Buffer, privateKey: Buffer}}
 */
function generateKeyPair(options) {
    if (options === void 0) { options = {}; }
    var type = options.type, _a = options.password, password = _a === void 0 ? new Buffer(0) : _a;
    if (type && Object.keys(KeyPairType).indexOf(type) === -1) {
        throw new VirgilCryptoError('Cannot generate keypair. Parameter "type" is invalid');
    }
    if (!isBuffer(password)) {
        throw new VirgilCryptoError('Cannot generate keypair. Parameter "password" must be a Buffer');
    }
    var keypair;
    try {
        if (type) {
            keypair = generate(lib.VirgilKeyPair.Type[type], password);
        }
        else {
            keypair = generateRecommended(password);
        }
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
    return {
        privateKey: virgilByteArrayToBuffer(keypair.privateKey()),
        publicKey: virgilByteArrayToBuffer(keypair.publicKey())
    };
}

var toDer = wrapFunction(lib.VirgilKeyPair.privateKeyToDER, lib.VirgilKeyPair);
/**
 * Converts PEM formatted private key to DER format.
 * @param {Buffer} privateKey - Private key in PEM format
 * @param {Buffer} [password] - Private key password, if encrypted.
 * @returns {Buffer} - Private key in DER format.
 * */
function privateKeyToDer(privateKey, password) {
    if (password === void 0) { password = new Buffer(0); }
    if (!isBuffer(privateKey)) {
        throw new VirgilCryptoError('Cannot convert private key to DER. Argument "privateKey" must be a Buffer');
    }
    if (!isBuffer(password)) {
        throw new VirgilCryptoError('Cannot convert private key to DER. Argument "password" must be a Buffer');
    }
    try {
        return toDer(privateKey, password);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

var toDer$1 = wrapFunction(lib.VirgilKeyPair.publicKeyToDER, lib.VirgilKeyPair);
/**
 * Converts PEM formatted public key to DER format.
 * @param {Buffer} publicKey - Public key in PEM format
 * @returns {Buffer} Public key in DER fromat.
 * */
function publicKeyToDer(publicKey) {
    if (!isBuffer(publicKey)) {
        throw new VirgilCryptoError('Cannot convert private key to DER. Argument "publicKey" must be a Buffer');
    }
    try {
        return toDer$1(publicKey);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

/**
 * Produces a hash of given data
 *
 * @param {Buffer} data - Data to hash
 * @param {string} [algorithm] - Hash algorithm to use. Default is SHA256
 *
 * @returns {Buffer}
 * */
function hash(data, algorithm) {
    if (algorithm === void 0) { algorithm = HashAlgorithm.SHA256; }
    if (!isBuffer(data)) {
        throw new VirgilCryptoError('Cannot calculate hash. Argument "data" must be a Buffer');
    }
    var virgilHash = new lib.VirgilHash(lib.VirgilHash["Algorithm_" + algorithm]);
    var hashFn = wrapFunction(virgilHash.hash, virgilHash);
    try {
        return hashFn(data);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

export { generateKeyPair, privateKeyToDer, publicKeyToDer, hash };
