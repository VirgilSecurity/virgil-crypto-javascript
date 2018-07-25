import { lib } from './lib/pythia-node';
import { Data } from './interfaces';
import { anyToBuffer } from './utils/anyToBuffer';
import { createPythiaWrapper } from './common';

const pythiaWrapper = createPythiaWrapper(lib);

/**
 * Result of the {@link VirgilPythiaCrypto.blind} method.
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
 * Input parameters of {@link VirgilPythiaCrypto.computeTransformationKeyPair} method.
 */
export interface PythiaComputeTransformationKeyPairParams {
	/**
	 * Key ID used in key pair computation.
	 */
	transformationKeyId: Data;

	/**
	 * Global secret key used in key pair computation.
	 */
	pythiaSecret: Data;

	/**
	 * Scope secret used in key pair derivation.
	 */
	pythiaScopeSecret: Data;
}

/**
 * Result of the {@link VirgilPythiaCrypto.computeTransformationKeyPair} method.
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
 * Input parameters of {@link VirgilPythiaCrypto.transform} method.
 */
export interface PythiaTransformParams {
	/**
	 * G1 Blinded (obfuscated) password.
	 */
	blindedPassword: Data;

	/**
	 * Some random value used to identify specific user.
	 */
	tweak: Data;

	/**
	 * BN transformation private key.
	 */
	transformationPrivateKey: Data;
}

/**
 * Result of the {@link VirgilPythiaCrypto.transform} method.
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
 * Input parameters of {@link VirgilPythiaCrypto.prove} method.
 */
export interface PythiaProveParams {
	/**
	 * GT transformed password from {@link VirgilPythiaCrypto.transform}.
	 */
	transformedPassword: Data;

	/**
	 * G1 blinded password from {@link VirgilPythiaCrypto.blind}.
	 */
	blindedPassword: Data;

	/**
	 * G2 transformed tweak from {@link VirgilPythiaCrypto.transform}.
	 */
	transformedTweak: Data;

	/**
	 * Transformation key pair from {@link VirgilPythiaCrypto.computeTransformationKeyPair}
	 */
	transformationKeyPair: PythiaTransformationKeyPair;
}

/**
 * Result of the {@link VirgilPythiaCrypto.prove} method.
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
 * Input parameters of {@link VirgilPythiaCrypto.verify} method.
 */
export interface PythiaVerifyParams {
	/**
	 * GT transformed password from {@link VirgilPythiaCrypto.transform}.
	 */
	transformedPassword: Data;

	/**
	 * G1 blinded password from {@link VirgilPythiaCrypto.blind}.
	 */
	blindedPassword: Data;

	/**
	 * The value used to identify the user.
	 */
	tweak: Data;

	/**
	 * G1 transformation public key.
	 */
	transformationPublicKey: Data;

	/**
	 * BN proof value C from {@link VirgilPythiaCrypto.prove}.
	 */
	proofValueC: Data;

	/**
	 * BN proof value U from {@link VirgilPythiaCrypto.prove}.
	 */
	proofValueU: Data;
}

/**
 * Input parameters of {@link VirgilPythiaCrypto.deblind} method.
 */
export interface PythiaDeblindParams {
	/**
	 * GT transformed password returned by {@link VirgilPythiaCrypto.transform}.
	 */
	transformedPassword: Data;

	/**
	 * BN value returned by {@link VirgilPythiaCrypto.blind}
	 */
	blindingSecret: Data;
}

/**
 * Input parameters of {@link VirgilPythiaCrypto.getPasswordUpdateToken} method.
 */
export interface PythiaGetPasswordUpdateTokenParams {
	/**
	 * The transformation private key used to transform the existing `deblindedPassword`'s.
	 */
	oldTransformationPrivateKey: Data;

	/**
	 * The new transformation private key.
	 */
	newTransformationPrivateKey: Data;
}

/**
 * Input parameters of {@link VirgilPythiaCrypto.updateDeblindedWithToken} method.
 */
export interface PythiaUpdateDeblindedWithTokenParams {
	/**
	 * GT Deblinded password to update.
	 */
	deblindedPassword: Data;

	/**
	 * BN Update token returned by {@link VirgilPythiaCrypto.getPasswordUpdateToken}.
	 */
	updateToken: Data;
}

/**
 * Class containing Pythia-related cryptographic operations.
 */
export class VirgilPythiaCrypto {

	/**
	 * Blinds (i.e. obfuscates) the password.
	 *
	 * Turns the password into a pseudo-random string.
	 * Blinding is necessary to prevent third-parties form knowing the end user's
	 * password.
	 *
	 * @param {Data} password - The user's password.
	 * @returns {PythiaBlindResult}
	 */
	blind (password: Data): PythiaBlindResult {
		const passwordBuf = anyToBuffer(password, 'utf8', 'password');
		return pythiaWrapper.blind(passwordBuf);
	}

	/**
	 * Deblinds the `transformedPassword` with the previously computed `blindingSecret`
	 * returned from {@link VirgilPythiaCrypto.blind} method.
	 *
	 * @param {PythiaDeblindParams} params - Input parameters.
	 *
	 * @returns {Buffer} - Deblinded password. This value is NOT equal to password
	 * and is zero-knowledge protected.
	 */
	deblind (params: PythiaDeblindParams): Buffer {
		const transformedPassword = anyToBuffer(
			params.transformedPassword, 'base64', 'params.transformedPassword'
		);
		const blindingSecret = anyToBuffer(
			params.blindingSecret, 'base64', 'params.blindingSecret'
		);

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
		const transformationKeyId = anyToBuffer(
			params.transformationKeyId, 'base64', 'params.transformationKeyId'
		);
		const pythiaSecret = anyToBuffer(
			params.pythiaSecret, 'base64', 'params.pythiaSecret'
		);
		const pythiaScopeSecret = anyToBuffer(
			params.pythiaScopeSecret, 'base64', 'params.pythiaScopeSecret'
		);
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
		const blindedPassword = anyToBuffer(
			params.blindedPassword, 'base64', 'params.blindedPassword'
		);
		const tweak = anyToBuffer(params.tweak, 'base64', 'params.tweak');
		const transformationPrivateKey = anyToBuffer(
			params.transformationPrivateKey, 'base64', 'params.transformationPrivateKey'
		);
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
		const transformationKeyPair = {
			privateKey: anyToBuffer(
				params.transformationKeyPair.privateKey,
				'base64',
				'params.transformationKeyPair.privateKey'
			),
			publicKey: anyToBuffer(
				params.transformationKeyPair.publicKey,
				'base64',
				'params.transformationKeyPair.publicKey'
			)
		};
		const transformedPassword = anyToBuffer(
			params.transformedPassword, 'base64', 'params.transformedPassword'
		);
		const blindedPassword = anyToBuffer(
			params.blindedPassword, 'base64', 'params.blindedPassword'
		);
		const transformedTweak = anyToBuffer(
			params.transformedTweak, 'base64', 'params.transformedTweak'
		);

		return pythiaWrapper.prove(transformedPassword, blindedPassword, transformedTweak, transformationKeyPair);
	}

	/**
	 * Verifies the cryptographic proof that the output of {@link VirgilPythiaCrypto.transform} is correct.
	 *
	 * @param {PythiaVerifyParams} params - Input parameters.
	 * @returns {boolean} - `true` if transformed password is correct, otherwise - `false`.
	 */
	verify (params: PythiaVerifyParams): boolean {
		const transformedPassword = anyToBuffer(
			params.transformedPassword, 'base64', 'params.transformedPassword'
		);
		const blindedPassword = anyToBuffer(
			params.blindedPassword, 'base64', 'params.blindedPassword'
		);
		const tweak = anyToBuffer(params.tweak, 'base64', 'params.tweak');
		const transformationPublicKey = anyToBuffer(
			params.transformationPublicKey, 'base64', 'params.transformationPublicKey'
		);
		const proofValueC = anyToBuffer(
			params.proofValueC, 'base64', 'params.proofValueC'
		);
		const proofValueU = anyToBuffer(
			params.proofValueU, 'base64', 'params.proofValueU'
		);

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
		const oldTransformationPrivateKey = anyToBuffer(
			params.oldTransformationPrivateKey, 'base64', 'params.oldTransformationPrivateKey'
		);
		const newTransformationPrivateKey = anyToBuffer(
			params.newTransformationPrivateKey, 'base64', 'params.newTransformationPrivateKey'
		);
		return pythiaWrapper.getPasswordUpdateToken(oldTransformationPrivateKey, newTransformationPrivateKey);
	}

	/**
	 * Generates new `deblindedPassword` by updating the existing one with the `updateToken`.
	 *
	 * @param {PythiaUpdateDeblindedWithTokenParams} params - Input parameters.
	 * @returns {Buffer} The new `deblindedPassword`
	 */
	updateDeblindedWithToken (params: PythiaUpdateDeblindedWithTokenParams): Buffer {
		const deblindedPassword = anyToBuffer(
			params.deblindedPassword, 'base64', 'params.deblindedPassword'
		);
		const updateToken = anyToBuffer(
			params.updateToken, 'base64', 'params.updateToken'
		);

		return pythiaWrapper.updateDeblindedWithToken(deblindedPassword, updateToken);
	}
}
