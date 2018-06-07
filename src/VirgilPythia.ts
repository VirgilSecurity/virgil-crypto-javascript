import { pythiaWrapper } from './pythia/node/wrapper';

/**
 * Input parameters of {@link VirgilPythia.computeTransformationKeyPair} method.
 */
export interface PythiaComputeTransformationKeyPairParams {
	/**
	 * Key ID used in key pair computation.
	 */
	transformationKeyId: Buffer;

	/**
	 * Global secret key used in key pair computation.
	 */
	pythiaSecret: Buffer;

	/**
	 * Scope secret used in key pair derivation.
	 */
	pythiaScopeSecret: Buffer;
}

/**
 * Input parameters of {@link VirgilPythia.deblind} method.
 */
export interface PythiaDeblindParams {
	/**
	 * GT transformed password returned by {@link VirgilPythia.transform}.
	 */
	transformedPassword: Buffer;

	/**
	 * BN value returned by {@link VirgilPythia.blind}
	 */
	blindingSecret: Buffer;
}

/**
 * Input parameters of {@link VirgilPythia.getPasswordUpdateToken} method.
 */
export interface PythiaGetPasswordUpdateTokenParams {
	/**
	 * The transformation private key used to transform the existing `deblindedPassword`'s.
	 */
	oldTransformationPrivateKey: Buffer;

	/**
	 * The new transformation private key.
	 */
	newTransformationPrivateKey: Buffer;
}

/**
 * Input parameters of {@link VirgilPythia.prove} method.
 */
export interface PythiaProveParams {
	/**
	 * GT transformed password from {@link VirgilPythia.transform}.
	 */
	transformedPassword: Buffer;

	/**
	 * G1 blinded password from {@link VirgilPythia.blind}.
	 */
	blindedPassword: Buffer;

	/**
	 * G2 transformed tweak from {@link VirgilPythia.transform}.
	 */
	transformedTweak: Buffer;

	/**
	 * Transformation key pair from {@link VirgilPythia.computeTransformationKeyPair}
	 */
	transformationKeyPair: PythiaTransformationKeyPair;
}

/**
 * Input parameters of {@link VirgilPythia.transform} method.
 */
export interface PythiaTransformParams {
	/**
	 * G1 Blinded (obfuscated) password.
	 */
	blindedPassword: Buffer;

	/**
	 * Some random value used to identify specific user.
	 */
	tweak: Buffer;

	/**
	 * BN transformation private key.
	 */
	transformationPrivateKey: Buffer;
}

/**
 * Input parameters of {@link VirgilPythia.updateDeblindedWithToken} method.
 */
export interface PythiaUpdateDeblindedWithTokenParams {
	/**
	 * GT Deblinded password to update.
	 */
	deblindedPassword: Buffer;

	/**
	 * BN Update token returned by {@link VirgilPythia.getPasswordUpdateToken}.
	 */
	updateToken: Buffer;
}

/**
 * Input parameters of {@link VirgilPythia.verify} method.
 */
export interface PythiaVerifyParams {
	/**
	 * GT transformed password from {@link VirgilPythia.transform}.
	 */
	transformedPassword: Buffer;

	/**
	 * G1 blinded password from {@link VirgilPythia.blind}.
	 */
	blindedPassword: Buffer;

	/**
	 * The value used to identify the user.
	 */
	tweak: Buffer;

	/**
	 * G1 transformation public key.
	 */
	transformationPublicKey: Buffer;

	/**
	 * BN proof value C from {@link VirgilPythia.prove}.
	 */
	proofValueC: Buffer;

	/**
	 * BN proof value U from {@link VirgilPythia.prove}.
	 */
	proofValueU: Buffer;
}

/**
 * Result of the {@link VirgilPythia.blind} method.
 */
export interface PythiaBlindResult {
	/**
	 * G1 password obfuscated into a pseudo-random string.
	 */
	blindedPassword: Buffer;

	/**
	 * BN random value used to blind user's password.
	 */
	blindingSecret: Buffer;
}

/**
 * Result of the {@link VirgilPythia.computeTransformationKeyPair} method.
 */
export interface PythiaTransformationKeyPair {
	/**
	 * BN transformation private key.
	 */
	privateKey: Buffer;

	/**
	 * G1 Transformation public key.
	 */
	publicKey: Buffer;
}

/**
 * Result of the {@link VirgilPythia.prove} method.
 */
export interface PythiaProveResult {
	/**
	 * BN first part of proof that `transformedPassword` was created using `transformationPrivateKey`.
	 */
	proofValueC: Buffer;

	/**
	 * BN second part of proof that `transformedPassword` was created using `transformationPrivateKey`.
	 */
	proofValueU: Buffer;
}

/**
 * Result of the {@link VirgilPythia.transform} method.
 */
export interface PythiaTransformResult {
	/**
	 * GT blinded password, protected using server secret (pythia_secret + pythia_scope_secret + tweak).
	 */
	transformedPassword: Buffer;

	/**
	 * G2 tweak value turned into an elliptic curve point. This value is used by Prove() operation.
	 */
	transformedTweak: Buffer;
}

/**
 * Class implementing Pythia-related cryptographic operations.
 */
export class VirgilPythia {

	/**
	 * Blinds (i.e. obfuscates) the password.
	 *
	 * Turns the password into a pseudo-random string.
	 * Blinding is necessary to prevent third-parties form knowing the end user's
	 * password.
	 *
	 * @param {string | Buffer} password - The user's password.
	 * @returns {PythiaBlindResult}
	 */
	blind (password: string | Buffer): PythiaBlindResult {
		return pythiaWrapper.blind(password);
	}

	/**
	 * Deblinds the `transformedPassword` with the previously computed `blindingSecret`
	 * returned from {@link VirgilPythia.blind} method.
	 *
	 * @param {PythiaDeblindParams} params - Input parameters.
	 *
	 * @returns {Buffer} - Deblinded password. This value is NOT equal to password
	 * and is zero-knowledge protected.
	 */
	deblind (params: PythiaDeblindParams): Buffer {
		const { transformedPassword, blindingSecret } = params;
		return pythiaWrapper.deblind(transformedPassword, blindingSecret);
	}

	/**
	 * Computes transformation private and public key.
	 *
	 * @param {PythiaComputeTransformationKeyPairParams} params - Input parameters.
	 *
	 * @returns {PythiaTransformationKeyPair}
	 */
	computeTransformationKeyPair (params: PythiaComputeTransformationKeyPairParams): PythiaTransformationKeyPair {
		const { transformationKeyId, pythiaSecret, pythiaScopeSecret } = params;
		return pythiaWrapper.computeTransformationKeyPair(
			transformationKeyId, pythiaSecret, pythiaScopeSecret
		);
	}

	/**
	 * Transforms blinded password using the private key, generated from `pythiaSecret` +
	 * `pythiaScopeSecret`.
	 * @param {PythiaTransformParams} params - Input parameters.
	 * @returns {PythiaTransformResult}
	 */
	transform (params: PythiaTransformParams): PythiaTransformResult {
		const { blindedPassword, tweak, transformationPrivateKey } = params;
		return pythiaWrapper.transform(blindedPassword, tweak, transformationPrivateKey);
	}

	/**
	 * Generates a cryptographic proof that one is in possession of the secret values
	 * that were used to transform the password.
	 *
	 * @param {PythiaProveParams} params - Input parameters.
	 * @returns {PythiaProveResult}
	 */
	prove (params: PythiaProveParams): PythiaProveResult {
		const { transformedPassword, blindedPassword, transformedTweak, transformationKeyPair } = params;
		return pythiaWrapper.prove(transformedPassword, blindedPassword, transformedTweak, transformationKeyPair);
	}

	/**
	 * Verifies the cryptographic proof that the output of {@link VirgilPythia.transform} is correct.
	 *
	 * @param {PythiaVerifyParams} params - Input parameters.
	 * @returns {boolean} - `true` if transformed password is correct, otherwise - `false`.
	 */
	verify (params: PythiaVerifyParams): boolean {
		const {
			transformedPassword,
			blindedPassword,
			tweak,
			transformationPublicKey,
			proofValueC,
			proofValueU
		} = params;

		return pythiaWrapper.verify(
			transformedPassword,
			blindedPassword,
			tweak,
			transformationPublicKey,
			proofValueC,
			proofValueU
		);
	}

	/**
	 * Computes the `updateToken` based on the old and new transformation private keys.
	 * An `updateToken` allows updating existing `deblindedPassword`'s when rotating the
	 * transformation private key in a way that it will match the original blinded password
	 * when transformed by the new transformation private key.
	 *
	 * When doing this, one should also change the `pythiaScopeSecret`.
	 *
	 * @param {PythiaGetPasswordUpdateTokenParams} params - Input parameters.
	 *
	 * @returns {Buffer}
	 */
	getPasswordUpdateToken (params: PythiaGetPasswordUpdateTokenParams): Buffer {
		const { oldTransformationPrivateKey, newTransformationPrivateKey } = params;
		return pythiaWrapper.getPasswordUpdateToken(oldTransformationPrivateKey, newTransformationPrivateKey);
	}

	/**
	 * Generates new `deblindedPassword` by updating the existing one with the `updateToken`.
	 *
	 * @param {PythiaUpdateDeblindedWithTokenParams} params - Input parameters.
	 * @returns {Buffer} The new `deblindedPassword`
	 */
	updateDeblindedWithToken (params: PythiaUpdateDeblindedWithTokenParams) {
		const { deblindedPassword, updateToken } = params;
		return pythiaWrapper.updateDeblindedWithToken(deblindedPassword, updateToken);
	}
}
