import * as cryptoApi from 'virgil-crypto-node';

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

var apply = Function.prototype.apply;

function toArray(val) {
    return Array.isArray(val)
        ? val
        : val === undefined ? val : [val];
}

var _privateKeys = new WeakMap();
var _setPrivateKeyValue = WeakMap.prototype.set;
var _getPrivateKeyValue = WeakMap.prototype.get;
var PrivateKey = /** @class */ (function () {
    function PrivateKey(identifier, value) {
        this.identifier = identifier;
        _setPrivateKeyValue.call(_privateKeys, this, value);
    }
    return PrivateKey;
}());
var PublicKey = /** @class */ (function () {
    function PublicKey(identifier, value) {
        this.identifier = identifier;
        this.value = value;
    }
    return PublicKey;
}());
function createVirgilCrypto(cryptoApi$$1) {
    return {
        generateKeys: generateKeys,
        importPrivateKey: importPrivateKey,
        importPublicKey: importPublicKey,
        exportPrivateKey: exportPrivateKey,
        exportPublicKey: exportPublicKey,
        extractPublicKey: extractPublicKey,
        encrypt: encrypt,
        decrypt: decrypt,
        calculateSignature: calculateSignature,
        verifySignature: verifySignature,
        calculateHash: calculateHash
    };
    /**
     * Generates a new key pair.
     *
     * @param {KeyPairType} [type] - Optional type of the key pair.
     * 			See {code: KeyPairType} for available options.
     * @returns {KeyPair} - The newly generated key pair.
     * */
    function generateKeys(type) {
        var keyPair = cryptoApi$$1.generateKeyPair({ type: type });
        var publicKeyDer = cryptoApi$$1.publicKeyToDer(keyPair.publicKey);
        var privateKeyDer = cryptoApi$$1.privateKeyToDer(keyPair.privateKey);
        var identifier = cryptoApi$$1.hash(publicKeyDer);
        return {
            privateKey: new PrivateKey(identifier, privateKeyDer),
            publicKey: new PublicKey(identifier, publicKeyDer)
        };
    }
    /**
     * Imports a private key from a Buffer or base64-encoded string
     * containing key material.
     *
     * @param {Buffer|string} rawPrivateKey - The private key material
     * 			as a {Buffer} or a string in base64.
     * @param {string} [password] - Optional password the key is
     * 			encrypted with.
     *
     * @returns {PrivateKey} - The private key object.
     * */
    function importPrivateKey(rawPrivateKey, password) {
        assert(Buffer.isBuffer(rawPrivateKey) || typeof rawPrivateKey === 'string', 'Cannot import private key. `rawPrivateKey` must be a Buffer or string in base64');
        rawPrivateKey = Buffer.isBuffer(rawPrivateKey) ? rawPrivateKey : Buffer.from(rawPrivateKey, 'base64');
        if (password) {
            rawPrivateKey = cryptoApi$$1.decryptPrivateKey(rawPrivateKey, Buffer.from(password, 'utf8'));
        }
        var privateKeyDer = cryptoApi$$1.privateKeyToDer(rawPrivateKey);
        var publicKey = cryptoApi$$1.extractPublicKey(privateKeyDer);
        var publicKeyDer = cryptoApi$$1.publicKeyToDer(publicKey);
        var identifier = cryptoApi$$1.hash(publicKeyDer);
        return new PrivateKey(identifier, privateKeyDer);
    }
    /**
     * Exports the private key handle into a Buffer containing the key bytes.
     *
     * @param {PrivateKey} privateKey - The private key object.
     * @param {string} [password] - Optional password to encrypt the key with.
     *
     * @returns {Buffer} - The private key bytes.
     * */
    function exportPrivateKey(privateKey, password) {
        var privateKeyValue = _getPrivateKeyValue.call(_privateKeys, privateKey);
        assert(privateKeyValue !== undefined, 'Cannot export private key. `privateKey` is invalid');
        if (password == null) {
            return privateKeyValue;
        }
        return cryptoApi$$1.encryptPrivateKey(privateKeyValue, Buffer.from(password, 'utf8'));
    }
    /**
     * Imports a public key from a Buffer or base64-encoded string
     * containing key material.
     *
     * @param {Buffer|string} rawPublicKey - The public key material
     * 			as a {Buffer} or base64-encoded string.
     *
     * @returns {PublicKey} - The imported key handle.
     * */
    function importPublicKey(rawPublicKey) {
        assert(Buffer.isBuffer(rawPublicKey) || typeof rawPublicKey === 'string', 'Cannot import public key. `rawPublicKey` must be a Buffer');
        rawPublicKey = Buffer.isBuffer(rawPublicKey) ? rawPublicKey : Buffer.from(rawPublicKey, 'base64');
        var publicKeyDer = cryptoApi$$1.publicKeyToDer(rawPublicKey);
        var identifier = cryptoApi$$1.hash(publicKeyDer);
        return new PublicKey(identifier, publicKeyDer);
    }
    /**
     * Exports the public key object into a Buffer containing the key bytes.
     *
     * @param {PublicKey} publicKey - The public key object.
     *
     * @returns {Buffer} - The public key bytes.
     * */
    function exportPublicKey(publicKey) {
        assert(publicKey !== undefined && publicKey.value !== undefined, 'Cannot import public key. `publicKey` is invalid');
        return publicKey.value;
    }
    /**
     * Encrypts the data for the recipient(s).
     *
     * @param {Buffer|string} data - The data to be encrypted as a {Buffer}
     * 			or a {string} in UTF8.
     * @param {PublicKey|PublicKey[]} publicKey - Public key or an array of public keys
     * of the intended recipients.
     *
     * @returns {Buffer} - Encrypted data.
     * */
    function encrypt(data, publicKey) {
        assert(typeof data === 'string' || Buffer.isBuffer(data), 'Cannot encrypt. `data` must be a string or Buffer');
        var publicKeys = toArray(publicKey);
        assert(publicKeys !== undefined && publicKeys.length > 0, 'Cannot encrypt. `publicKey` must not be empty');
        data = Buffer.isBuffer(data) ? data : Buffer.from(data);
        return cryptoApi$$1.encrypt(data, publicKeys.map(function (pubkey) { return ({
            identifier: pubkey.identifier,
            publicKey: pubkey.value
        }); }));
    }
    /**
     * Decrypts the data with the private key.
     *
     * @param {Buffer|string} encryptedData - The data to be decrypted as
     * 			a {Buffer} or a {string} in base64.
     * @param {PrivateKey} privateKey - The private key to decrypt with.
     *
     * @returns {Buffer} - Decrypted data
     * */
    function decrypt(encryptedData, privateKey) {
        assert(typeof encryptedData === 'string' || Buffer.isBuffer(encryptedData), 'Cannot decrypt. `data` must be a Buffer or a string in base64');
        encryptedData = Buffer.isBuffer(encryptedData) ? encryptedData : Buffer.from(encryptedData, 'base64');
        var privateKeyValue = _getPrivateKeyValue.call(_privateKeys, privateKey);
        assert(privateKeyValue !== undefined, 'Cannot decrypt. `privateKey` is invalid');
        return cryptoApi$$1.decrypt(encryptedData, {
            identifier: privateKey.identifier,
            privateKey: privateKeyValue
        });
    }
    /**
     * Calculates the hash of the given data.
     *
     * @param {Buffer|string} data - The data to calculate the hash of as a
     * 			{Buffer} or a {string} in UTF-8.
     * @param {string} [algorithm] - Optional name of the hash algorithm
     * 		to use. See { code: virgilCrypto.HashAlgorithm }
     * 		for available options. Default is SHA256.
     *
     * @returns {Buffer} - The hash.
     * */
    function calculateHash(data, algorithm) {
        if (algorithm === void 0) { algorithm = HashAlgorithm.SHA256; }
        assert(Buffer.isBuffer(data) || typeof data === 'string', 'Cannot calculate hash. `data` must be a Buffer or a string in base64');
        data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        return cryptoApi$$1.hash(data, algorithm);
    }
    /**
     * Extracts a public key from the private key handle.
     *
     * @param {PrivateKey} privateKey - The private key object to extract from.
     *
     * @returns {PublicKey} - The handle to the extracted public key.
     * */
    function extractPublicKey(privateKey) {
        var privateKeyValue = _getPrivateKeyValue.call(_privateKeys, privateKey);
        assert(privateKeyValue !== undefined, 'Cannot extract public key. `privateKey` is invalid');
        var publicKey = cryptoApi$$1.extractPublicKey(privateKeyValue);
        return new PublicKey(privateKey.identifier, publicKey);
    }
    /**
     * Calculates the signature of the data using the private key.
     *
     * @param {Buffer|string} data - The data to be signed as a Buffer or a string in UTF-8.
     * @param {PrivateKey} privateKey - The private key object.
     *
     * @returns {Buffer} - The signature.
     * */
    function calculateSignature(data, privateKey) {
        assert(Buffer.isBuffer(data) || typeof data === 'string', 'Cannot calculate signature. `data` must be a Buffer or a string');
        var privateKeyValue = _getPrivateKeyValue.call(_privateKeys, privateKey);
        assert(privateKeyValue !== undefined, 'Cannot calculate signature. `privateKey` is invalid');
        data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        return cryptoApi$$1.sign(data, privateKeyValue);
    }
    /**
     * Verifies the provided data using the given signature and public key.
     *
     * @param {Buffer|string} data - The data to be verified as a {Buffer}
     * 			or a {string} in UTF-8.
     * @param {Buffer|string} signature - The signature as a {Buffer} or a
     * 			{string} in base64.
     * @param {PublicKey} publicKey - The public key object.
     *
     * @returns {boolean} - True or False depending on the
     * 			validity of the signature for the data and public key.
     * */
    function verifySignature(data, signature, publicKey) {
        assert(Buffer.isBuffer(data) || typeof data === 'string', 'Cannot verify signature. `data` must be a Buffer or a string');
        assert(Buffer.isBuffer(signature) || typeof signature === 'string', 'Cannot verify signature. `signature` must be a Buffer or a string');
        assert(publicKey != null && Buffer.isBuffer(publicKey.value), 'Cannot verify signature. `publicKey` is invalid');
        data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        signature = Buffer.isBuffer(signature) ? signature : Buffer.from(signature, 'base64');
        return cryptoApi$$1.verify(data, signature, publicKey.value);
    }
}

var crypto = createVirgilCrypto(cryptoApi);

export { KeyPairType, HashAlgorithm, crypto };
