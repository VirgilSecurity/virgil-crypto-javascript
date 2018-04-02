'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var lib = _interopDefault(require('../virgil_crypto_node.node'));

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
    // "Module: virgil/crypto. Error code: {code}. {message}."
    var parts = virgilCryptoMessage.split(/\s*\.\s*/);
    if (parts.length === 1) {
        // Error message didn't match what we expected.
        return err;
    }
    var code = parts[1], message = parts[2];
    return new VirgilCryptoError(message, code, name);
}
function assert(condition, message) {
    if (!condition) {
        throw new VirgilCryptoError(message);
    }
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

function toArray(val) {
    return Array.isArray(val)
        ? val
        : val === undefined ? val : [val];
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
var toString = Object.prototype.toString;
function isVirgilByteArray(obj) {
    if (obj == null) {
        return false;
    }
    var tag = toString.call(obj);
    return tag === '[object _exports_VirgilByteArray]' || tag === '[object VirgilByteArray]';
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
    assert(type === undefined || Object.keys(KeyPairType).indexOf(type) !== -1, 'Cannot generate keypair. Parameter "type" is invalid');
    assert(isBuffer(password), 'Cannot generate keypair. Parameter "password" must be a Buffer');
    var keypair;
    try {
        if (type) {
            keypair = generate(lib.VirgilKeyPair["Type_" + type], password);
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
    assert(isBuffer(privateKey), 'Cannot convert private key to DER. Argument "privateKey" must be a Buffer');
    assert(isBuffer(password), 'Cannot convert private key to DER. Argument "password" must be a Buffer');
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
    assert(isBuffer(publicKey), 'Cannot convert private key to DER. Argument "publicKey" must be a Buffer');
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
    assert(isBuffer(data), 'Cannot calculate hash. Argument "data" must be a Buffer');
    var virgilHash = new lib.VirgilHash(lib.VirgilHash["Algorithm_" + algorithm]);
    var hashFn = wrapFunction(virgilHash.hash, virgilHash);
    try {
        return hashFn(data);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

/**
 * Encrypt data.
 *
 * @param data {Buffer} - Data to encrypt.
 * @param encryptionKey {EncryptionKey|EncryptionKey[]} - Public key with identifier or an array of
 * public keys with identifiers to encrypt with.
 *
 * @returns {Buffer} - Encrypted data.
 */
function encrypt(data, encryptionKey) {
    var encryptionKeys = toArray(encryptionKey);
    assert(isBuffer(data), 'Cannot encrypt. `data` must be a Buffer');
    assert(encryptionKey !== undefined, 'Cannot encrypt. `encryptionKey` is required');
    assert(encryptionKeys.length > 0, 'Cannot encrypt. `encryptionKey` must not be empty');
    encryptionKeys.forEach(function (_a) {
        var identifier = _a.identifier, publicKey = _a.publicKey;
        assert(isBuffer(identifier), 'Cannot encrypt. Public key identifier must be a Buffer.');
        assert(isBuffer(publicKey), 'Cannot encrypt. Public key must me a Buffer');
    });
    var cipher = new lib.VirgilCipher();
    var addKeyRecipientFn = wrapFunction(cipher.addKeyRecipient, cipher);
    var encryptFn = wrapFunction(cipher.encrypt, cipher);
    try {
        encryptionKeys.forEach(function (_a) {
            var identifier = _a.identifier, publicKey = _a.publicKey;
            addKeyRecipientFn(identifier, publicKey);
        });
        return encryptFn(data, true);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

/**
 * Decrypt data
 *
 * @param encryptedData {Buffer} - The data to decrypt.
 * @param decryptionKey {DecryptionKey} - Private key with identifier and optional password.
 * @returns {Buffer} - Decrypted data.
 */
function decrypt(encryptedData, decryptionKey) {
    assert(isBuffer(encryptedData), 'Cannot decrypt. `encryptedData` must be a Buffer');
    assert(decryptionKey !== undefined, 'Cannot decrypt. `decryptionKey` is required');
    var identifier = decryptionKey.identifier, privateKey = decryptionKey.privateKey, _a = decryptionKey.privateKeyPassword, privateKeyPassword = _a === void 0 ? new Buffer(0) : _a;
    assert(isBuffer(identifier) &&
        isBuffer(privateKey) &&
        (privateKeyPassword === undefined || isBuffer(privateKeyPassword)), 'Cannot decrypt. `decryptionKey` is invalid');
    var cipher = new lib.VirgilCipher();
    var decryptWithKeyFn = wrapFunction(cipher.decryptWithKey, cipher);
    try {
        return decryptWithKeyFn(encryptedData, identifier, privateKey, privateKeyPassword);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

var encryptPrivateKeyFn = wrapFunction(lib.VirgilKeyPair.encryptPrivateKey, lib.VirgilKeyPair);
/**
 * Encrypts the private key with password
 *
 * @param {Buffer} privateKey - Private key to encrypt
 * @param {Buffer} password - Password to encrypt the private key with
 *
 * @returns {Buffer} - Encrypted private key
 * */
function encryptPrivateKey(privateKey, password) {
    assert(isBuffer(privateKey), 'Cannot encrypt private key. `privateKey` must be a Buffer');
    assert(isBuffer(password), 'Cannot encrypt private key. `password` must be a Buffer');
    try {
        return encryptPrivateKeyFn(privateKey, password);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

var decryptPrivateKeyFn = wrapFunction(lib.VirgilKeyPair.decryptPrivateKey, lib.VirgilKeyPair);
/**
 * Decrypts encrypted private key.
 * @param {Buffer} privateKey - Private key to decrypt.
 * @param {Buffer} [password] - Private key password.
 *
 * @returns {Buffer} - Decrypted private key
 * */
function decryptPrivateKey(privateKey, password) {
    assert(isBuffer(privateKey), 'Cannot decrypt private key. `privateKey` must be a Buffer');
    assert(isBuffer(password), 'Cannot decrypt private key. `password` must be a Buffer');
    try {
        return decryptPrivateKeyFn(privateKey, password);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

var extractPublicKeyFn = wrapFunction(lib.VirgilKeyPair.extractPublicKey, lib.VirgilKeyPair);
/**
 * Extracts public key out of private key.
 *
 * @param {Buffer} privateKey - Private key to extract from.
 * @param {Buffer} [password] - Private key password if private key is encrypted.
 *
 * @returns {Buffer} - Extracted public key
 * */
function extractPublicKey(privateKey, password) {
    if (password === void 0) { password = new Buffer(0); }
    assert(isBuffer(privateKey), 'Cannot extract public key. `privateKey` must be a Buffer');
    assert(isBuffer(password), 'Cannot extract public key. `password` must be a Buffer');
    try {
        return extractPublicKeyFn(privateKey, password);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

/**
 * Calculates the digital signature of the given data using the given private key.
 *
 * @param data {Buffer} - Data to sign.
 * @param privateKey {Buffer} - Private key to use.
 * @param [privateKeyPassword] {Buffer} - Optional password the private key is encrypted with.
 * @returns {Buffer} - Digital signature.
 */
function sign(data, privateKey, privateKeyPassword) {
    if (privateKeyPassword === void 0) { privateKeyPassword = new Buffer(0); }
    var signer = new lib.VirgilSigner();
    var signFn = wrapFunction(signer.sign, signer);
    try {
        return signFn(data, privateKey, privateKeyPassword);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

/**
 * Verifies digital signature of the given data for the given public key.
 *
 * @param data {Buffer} - Data to verify.
 * @param signature {Buffer} - The signature.
 * @param publicKey {Buffer} - The public key.
 *
 * @returns {boolean} - True if signature is valid for the given public key and data,
 * otherwise False.
 */
function verify(data, signature, publicKey) {
    var signer = new lib.VirgilSigner();
    var verifyFn = wrapFunction(signer.verify, signer);
    try {
        return verifyFn(data, signature, publicKey);
    }
    catch (e) {
        throw errorFromNativeError(e);
    }
}

exports.generateKeyPair = generateKeyPair;
exports.privateKeyToDer = privateKeyToDer;
exports.publicKeyToDer = publicKeyToDer;
exports.hash = hash;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.encryptPrivateKey = encryptPrivateKey;
exports.decryptPrivateKey = decryptPrivateKey;
exports.extractPublicKey = extractPublicKey;
exports.sign = sign;
exports.verify = verify;
