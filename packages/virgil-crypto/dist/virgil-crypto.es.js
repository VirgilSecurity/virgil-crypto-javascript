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

var _privateKeys = new WeakMap();
var _setPrivateKeyValue = WeakMap.prototype.set;
// const _getPrivateKeyValue = WeakMap.prototype.get;
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
}

var crypto = createVirgilCrypto(cryptoApi);

export { KeyPairType, HashAlgorithm, crypto };
