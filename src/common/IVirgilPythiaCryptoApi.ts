export interface BlindResult {
	blindedPassword: Buffer;
	blindingSecret: Buffer;
}

export interface TransformationKeyPair {
	privateKey: Buffer;
	publicKey: Buffer;
}

export interface ProveResult {
	proofValueC: Buffer;
	proofValueU: Buffer;
}

export interface TransformResult {
	transformedPassword: Buffer;
	transformedTweak: Buffer;
}

export interface IVirgilPythiaCryptoApi {
	blind (password: string | Buffer): BlindResult;

	computeTransformationKeyPair (
		transformationKeyId: Buffer,
		pythiaSecret: Buffer,
		pythiaScopeSecret: Buffer
	): TransformationKeyPair;

	deblind (transformedPassword: Buffer, blindingSecret: Buffer): Buffer;

	generateSalt (numOfBytes?: number): Buffer;

	getPasswordUpdateToken (oldTransformationPrivateKey: Buffer, newTransformationPrivateKey: Buffer): Buffer;

	prove (
		transformedPassword: Buffer,
		blindedPassword: Buffer,
		transformedTweak: Buffer,
		transformationKeyPair: { privateKey: Buffer, publicKey: Buffer }
	): ProveResult;

	transform (blindedPassword: Buffer, tweak: Buffer, transformationPrivateKey: Buffer): TransformResult;

	updateDeblindedWithToken (deblindedPassword: Buffer, passwordUpdateToken: Buffer): Buffer;

	verify (
		transformedPassword: Buffer,
		blindedPassword: Buffer,
		tweak: Buffer,
		transformationPublicKey: Buffer,
		proofValueC: Buffer,
		proofValueU: Buffer
	): boolean;
}
