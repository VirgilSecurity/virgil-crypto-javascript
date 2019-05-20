import './virgil_crypto_pythia_asmjs.js';

const minMemory = 1024 * 1024 * 16; // 16 MB - emscripten default
const globalScope: any = typeof self !== 'undefined' ? self : global;

let totalMemory = parseInt(globalScope.__VIRGIL_CRYPTO_TOTAL_MEMORY_BYTES__, 10);
totalMemory = isNaN(totalMemory) ? minMemory : Math.max(totalMemory, minMemory);

const lib = __virgilCrypto({
	TOTAL_MEMORY: totalMemory
});
// tslint:disable-next-line:ter-prefer-arrow-callback
lib.setDelayFunction(function (delayed: Function) {
	setTimeout(delayed, 0);
});

export { lib };
