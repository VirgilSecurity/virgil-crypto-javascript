import { createNativeTypeWrapper } from './createNativeTypeWrapper';

/**
 * Creates a wrapper for Pythia-related crypto operations.
 *
 * @hidden
 *
 * @param lib - Native VirgilCrypto library (browser or node.js).
 */
export function createPythiaWrapper (lib: any) {
	if (typeof lib.VirgilPythia !== 'function') {
		return null;
	}

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
		return new lib.VirgilPythia();
	};

	const createVirgilPythiaTransformationKeyPair = (privateKey: Buffer, publicKey: Buffer) => {
		const privateKeyArr = wrapper.utils.bufferToVirgilByteArray(privateKey);
		const publicKeyArr = wrapper.utils.bufferToVirgilByteArray(publicKey);
		const keyPair = new lib.VirgilPythiaTransformationKeyPair(
			privateKeyArr,
			publicKeyArr
		);

		const freeMem = process.browser ? function () {
			privateKeyArr.delete();
			publicKeyArr.delete();
			keyPair.delete();
		} : function() {};

		return { keyPair, freeMem };
	};

	return {
		blind (password: Buffer) {
			const pythia = createVirgilPythia();

			const result = pythia.blindSafe(password);
			const blindedPasswordArr = result.blindedPassword();
			const blindingSecretArr = result.blindingSecret();

			const retVal = {
				blindedPassword: wrapper.utils.virgilByteArrayToBuffer(blindedPasswordArr),
				blindingSecret: wrapper.utils.virgilByteArrayToBuffer(blindingSecretArr)
			};

			if (process.browser) {
				pythia.delete();
				blindedPasswordArr.delete();
				blindingSecretArr.delete();
				result.delete();
			}

			return retVal;
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

			const retVal = {
				privateKey: wrapper.utils.virgilByteArrayToBuffer(privateKeyArr),
				publicKey: wrapper.utils.virgilByteArrayToBuffer(publicKeyArr)
			};

			if (process.browser) {
				pythia.delete();
				privateKeyArr.delete();
				publicKeyArr.delete();
				keyPair.delete();
			}

			return retVal;
		},

		deblind (transformedPassword: Buffer, blindingSecret: Buffer): Buffer {
			const pythia = createVirgilPythia();
			const retVal = pythia.deblindSafe(transformedPassword, blindingSecret);
			if (process.browser) pythia.delete();
			return retVal;
		},

		getPasswordUpdateToken (oldTransformationPrivateKey: Buffer, newTransformationPrivateKey: Buffer): Buffer {
			const pythia = createVirgilPythia();
			const retVal = pythia.getPasswordUpdateTokenSafe(
				oldTransformationPrivateKey,
				newTransformationPrivateKey
			);
			if (process.browser) pythia.delete();
			return retVal;
		},

		prove (
			transformedPassword: Buffer,
			blindedPassword: Buffer,
			transformedTweak: Buffer,
			transformationKeyPair: { privateKey: Buffer, publicKey: Buffer }
		) {
			const pythiaTransformationKeyPair = createVirgilPythiaTransformationKeyPair(
				transformationKeyPair.privateKey,
				transformationKeyPair.publicKey
			);

			const pythia = createVirgilPythia();
			const result = pythia.proveSafe(
				transformedPassword,
				blindedPassword,
				transformedTweak,
				pythiaTransformationKeyPair.keyPair
			);

			const proofValueCArr = result.proofValueC();
			const proofValueUArr = result.proofValueU();

			const retVal = {
				proofValueC: wrapper.utils.virgilByteArrayToBuffer(proofValueCArr),
				proofValueU: wrapper.utils.virgilByteArrayToBuffer(proofValueUArr),
			}

			if (process.browser) {
				pythia.delete();
				pythiaTransformationKeyPair.freeMem();
				proofValueCArr.delete();
				proofValueUArr.delete();
				result.delete();
			}

			return retVal;
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

			const retVal = {
				transformedPassword: wrapper.utils.virgilByteArrayToBuffer(transformedPasswordArr),
				transformedTweak: wrapper.utils.virgilByteArrayToBuffer(transformedTweakArr),
			};

			if (process.browser) {
				pythia.delete();
				transformedPasswordArr.delete();
				transformedTweakArr.delete();
				result.delete();
			}

			return retVal;
		},

		updateDeblindedWithToken (deblindedPassword: Buffer, passwordUpdateToken: Buffer): Buffer {
			if (deblindedPassword == null) throw new Error('`deblindedPassword` is required');
			if (passwordUpdateToken == null) throw new Error('`passwordUpdateToken` is required');

			const pythia = createVirgilPythia();
			const retVal = pythia.updateDeblindedWithTokenSafe(deblindedPassword, passwordUpdateToken);
			if (process.browser) pythia.delete();
			return retVal;
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
			const retVal = pythia.verifySafe(
				transformedPassword,
				blindedPassword,
				tweak,
				transformationPublicKey,
				proofValueC,
				proofValueU
			);

			if (process.browser) pythia.delete();
			return retVal;
		}
	}
}
