import './virgil_crypto_asmjs.js';

const minMemory = 1024 * 1024 * 16; // 16 MB - emscripten default

let totalMemory = parseInt((window as any).__VIRGIL_CRYPTO_TOTAL_MEMORY_BYTES__, 10);
totalMemory = isNaN(totalMemory) ? minMemory : Math.max(totalMemory, minMemory);

const lib = __virgilCrypto({
	TOTAL_MEMORY: totalMemory
});
lib.setDelayFunction(function (delayed: Function) {
	setTimeout(delayed, 0);
});

export { lib };
