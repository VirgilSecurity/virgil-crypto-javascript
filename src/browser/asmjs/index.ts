import './virgil_crypto_asmjs.js';

const lib = __virgilCrypto();
lib.setDelayFunction(function (delayed: Function) {
	setTimeout(delayed, 0);
});

export { lib };
