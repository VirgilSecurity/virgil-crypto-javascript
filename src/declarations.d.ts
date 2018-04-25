declare module NodeJS {
	interface Process {
		browser?: boolean;
	}
}

declare module '*/virgil_crypto_asmjs.js' {
	const __virgilCrypto: Function;
	export default __virgilCrypto;
}

declare module '*.node' {
	const VirgilCrypto: any;
	export default VirgilCrypto;
}

declare var __virgilCrypto: Function;
