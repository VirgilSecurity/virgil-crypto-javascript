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

var apply = Function.prototype.apply;
var hasOwn = Object.prototype.hasOwnProperty;
function createNativeWrapper(utils) {
    var wrapNativeFunction;
    {
        wrapNativeFunction = function wrapNativeFunctionNode(fn, target) {
            return function () {
                var args = [];
                for (var _i = 0; _i < arguments.length; _i++) {
                    args[_i] = arguments[_i];
                }
                var transformedArgs = args.map(function (arg) { return utils.isBuffer(arg) ? utils.bufferToVirgilByteArray(arg) : arg; });
                var result = apply.call(fn, target || this, transformedArgs);
                if (utils.isVirgilByteArray(result)) {
                    result = utils.virgilByteArrayToBuffer(result);
                }
                return result;
            };
        };
    }
    return {
        createSafeInstanceMethods: createSafeInstanceMethods,
        createSafeStaticMethods: createSafeStaticMethods
    };
    function createSafeInstanceMethods(ctor, methods) {
        var proto = ctor.prototype;
        methods.forEach(function (method) {
            if (!(method in proto) || typeof proto[method] !== 'function') {
                throw new TypeError("Method \"" + method + "\" does not exist on " + ctor.name + " prototype");
            }
            // cannot replace the method on the prototype as there are additional properties
            // associated with class prototype methods generated by emscripten
            // cannot replace the prototype either as it is used for reference
            // equality check during construction of instances (e.g. new VirgilHash()
            // fails if we replace the `VirgilHash.prototype` with a custom object)
            proto[method + 'Safe'] = wrapNativeFunction(proto[method]);
        });
    }
    function createSafeStaticMethods(ctor, methods) {
        methods.forEach(function (method) {
            if (!hasOwn.call(ctor, method) || typeof ctor[method] !== 'function') {
                throw new TypeError("Method \"" + method + "\" does not exist on " + ctor.name);
            }
            // adding Safe suffix for consistency with instance methods
            ctor[method + 'Safe'] = wrapNativeFunction(ctor[method]);
        });
    }
}

function toArray(val) {
    return Array.isArray(val)
        ? val
        : val === undefined ? val : [val];
}

export { HashAlgorithm, KeyPairType, createNativeWrapper, toArray, VirgilCryptoError, errorFromNativeError, assert };
