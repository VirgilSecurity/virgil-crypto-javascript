declare module NodeJS {
	interface Process {
		browser?: boolean;
	}
}

declare module '*/virgil_crypto_asmjs.js';

declare module '*/virgil_crypto_pythia_asmjs.js';

declare module '*.node';

declare var __virgilCrypto: Function;
