import { createNativeTypeWrapper } from './createNativeTypeWrapper';

/**
 * Creates a wrapper for Pythia-related crypto operations.
 *
 * @hidden
 *
 * @param lib - Native VirgilCrypto library (browser or node.js).
 */
export function createPythiaWrapper (lib: any) {
	const wrapper = createNativeTypeWrapper(lib);

	wrapper.createSafeInstanceMethods(
		lib.VirgilPythia,
		[
			'blind',
			'computeTransformationKeyPair',
			'deblind',
			'getPasswordUpdateToken',
			'prove',
			'transform',
			'updateDeblindedWithToken',
			'verify'
		]
	);

	const createVirgilPythia = () => {
		const pythia = new lib.VirgilPythia();
		if (process.browser) pythia.deleteLater();
		return pythia;
	};

	const createVirgilPythiaTransformationKeyPair = (privateKey: Buffer, publicKey: Buffer) => {
		const privateKeyArr = wrapper.utils.bufferToVirgilByteArray(privateKey);
		const publicKeyArr = wrapper.utils.bufferToVirgilByteArray(publicKey);
		const keyPair = new lib.VirgilPythiaTransformationKeyPair(
			privateKeyArr,
			publicKeyArr
		);

		if (process.browser) {
			privateKeyArr.deleteLater();
			publicKeyArr.deleteLater();
			keyPair.deleteLater();
		}

		return keyPair;
	};

	return {
		blind (password: Buffer) {
			const pythia = createVirgilPythia();

			const result = pythia.blindSafe(password);
			const blindedPasswordArr = result.blindedPassword();
			const blindingSecretArr = result.blindingSecret();

			if (process.browser) {
				blindedPasswordArr.deleteLater();
				blindingSecretArr.deleteLater();
				result.deleteLater();
			}

			return {
				blindedPassword: wrapper.utils.virgilByteArrayToBuffer(blindedPasswordArr),
				blindingSecret: wrapper.utils.virgilByteArrayToBuffer(blindingSecretArr)
			};
		},

		computeTransformationKeyPair (transformationKeyId: Buffer, pythiaSecret: Buffer, pythiaScopeSecret: Buffer) {
			const pythia = createVirgilPythia();
			const keyPair = pythia.computeTransformationKeyPairSafe(
				transformationKeyId,
				pythiaSecret,
				pythiaScopeSecret
			);

			const privateKeyArr = keyPair.privateKey();
			const publicKeyArr = keyPair.publicKey();

			if (process.browser) {
				privateKeyArr.deleteLater();
				publicKeyArr.deleteLater();
				keyPair.deleteLater();
			}

			return {
				privateKey: wrapper.utils.virgilByteArrayToBuffer(privateKeyArr),
				publicKey: wrapper.utils.virgilByteArrayToBuffer(publicKeyArr)
			};
		},

		deblind (transformedPassword: Buffer, blindingSecret: Buffer): Buffer {
			const pythia = createVirgilPythia();
			return pythia.deblindSafe(transformedPassword, blindingSecret);
		},

		getPasswordUpdateToken (oldTransformationPrivateKey: Buffer, newTransformationPrivateKey: Buffer): Buffer {
			const pythia = createVirgilPythia();
			return pythia.getPasswordUpdateTokenSafe(
				oldTransformationPrivateKey,
				newTransformationPrivateKey
			);
		},

		prove (
			transformedPassword: Buffer,
			blindedPassword: Buffer,
			transformedTweak: Buffer,
			transformationKeyPair: { privateKey: Buffer, publicKey: Buffer }
		) {
			transformationKeyPair = createVirgilPythiaTransformationKeyPair(
				transformationKeyPair.privateKey,
				transformationKeyPair.publicKey
			);

			const pythia = createVirgilPythia();
			const result = pythia.proveSafe(
				transformedPassword,
				blindedPassword,
				transformedTweak,
				transformationKeyPair
			);

			const proofValueCArr = result.proofValueC();
			const proofValueUArr = result.proofValueU();

			if (process.browser) {
				proofValueCArr.deleteLater();
				proofValueUArr.deleteLater();
				result.deleteLater();
			}

			return {
				proofValueC: wrapper.utils.virgilByteArrayToBuffer(proofValueCArr),
				proofValueU: wrapper.utils.virgilByteArrayToBuffer(proofValueUArr),
			}
		},

		transform (blindedPassword: Buffer, tweak: Buffer, transformationPrivateKey: Buffer) {
			const pythia = createVirgilPythia();
			const result = pythia.transformSafe(
				blindedPassword,
				tweak,
				transformationPrivateKey
			);

			const transformedPasswordArr = result.transformedPassword();
			const transformedTweakArr = result.transformedTweak();

			if (process.browser) {
				transformedPasswordArr.deleteLater();
				transformedTweakArr.deleteLater();
				result.deleteLater();
			}

			return {
				transformedPassword: wrapper.utils.virgilByteArrayToBuffer(transformedPasswordArr),
				transformedTweak: wrapper.utils.virgilByteArrayToBuffer(transformedTweakArr),
			};
		},

		updateDeblindedWithToken (deblindedPassword: Buffer, passwordUpdateToken: Buffer): Buffer {
			if (deblindedPassword == null) throw new Error('`deblindedPassword` is required');
			if (passwordUpdateToken == null) throw new Error('`passwordUpdateToken` is required');

			const pythia = createVirgilPythia();
			return pythia.updateDeblindedWithTokenSafe(deblindedPassword, passwordUpdateToken);
		},

		verify (
			transformedPassword: Buffer,
			blindedPassword: Buffer,
			tweak: Buffer,
			transformationPublicKey: Buffer,
			proofValueC: Buffer,
			proofValueU: Buffer
		): boolean {
			const pythia = createVirgilPythia();
			return pythia.verifySafe(
				transformedPassword,
				blindedPassword,
				tweak,
				transformationPublicKey,
				proofValueC,
				proofValueU
			);
		}
	}
}
