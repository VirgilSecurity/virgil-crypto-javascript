import __virgilCrypto from './virgil_crypto_asmjs.js';

const lib = __virgilCrypto({ ENVIRONMENT: 'WEB' });
lib.setDelayFunction(function (delayed: Function) {
	setTimeout(delayed, 0);
});

export { lib };
