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
			let result: any;
			let blindedPasswordArr: any;
			let blindingSecretArr: any;

			try {
				result = pythia.blindSafe(password);
				blindedPasswordArr = result.blindedPassword();
				blindingSecretArr = result.blindingSecret();

				return {
					blindedPassword: wrapper.utils.virgilByteArrayToBuffer(blindedPasswordArr),
					blindingSecret: wrapper.utils.virgilByteArrayToBuffer(blindingSecretArr)
				};
			} finally {
				if (process.browser) {
					pythia.delete();
					blindedPasswordArr &&  blindedPasswordArr.delete();
					blindingSecretArr && blindingSecretArr.delete();
					result && result.delete();
				}
			}
		},

		computeTransformationKeyPair (transformationKeyId: Buffer, pythiaSecret: Buffer, pythiaScopeSecret: Buffer) {
			const pythia = createVirgilPythia();
			let keyPair: any;
			let privateKeyArr: any;
			let publicKeyArr: any;

			try {
				keyPair = pythia.computeTransformationKeyPairSafe(
					transformationKeyId,
					pythiaSecret,
					pythiaScopeSecret
				);

				privateKeyArr = keyPair.privateKey();
				publicKeyArr = keyPair.publicKey();

				return {
					privateKey: wrapper.utils.virgilByteArrayToBuffer(privateKeyArr),
					publicKey: wrapper.utils.virgilByteArrayToBuffer(publicKeyArr)
				};
			} finally {
				if (process.browser) {
					pythia.delete();
					privateKeyArr && privateKeyArr.delete();
					publicKeyArr && publicKeyArr.delete();
					keyPair && keyPair.delete();
				}
			}
		},

		deblind (transformedPassword: Buffer, blindingSecret: Buffer): Buffer {
			const pythia = createVirgilPythia();
			try {
				return pythia.deblindSafe(transformedPassword, blindingSecret);
			} finally {
				if (process.browser) pythia.delete();
			}
		},

		getPasswordUpdateToken (oldTransformationPrivateKey: Buffer, newTransformationPrivateKey: Buffer): Buffer {
			const pythia = createVirgilPythia();
			try {
				return pythia.getPasswordUpdateTokenSafe(
					oldTransformationPrivateKey,
					newTransformationPrivateKey
				);
			} finally {
				if (process.browser) pythia.delete();
			}
		},

		prove (
			transformedPassword: Buffer,
			blindedPassword: Buffer,
			transformedTweak: Buffer,
			transformationKeyPair: { privateKey: Buffer, publicKey: Buffer }
		) {
			const pythia = createVirgilPythia();

			let pythiaTransformationKeyPair: { keyPair: any, freeMem: () => void }|undefined;
			let result: any;
			let proofValueCArr: any;
			let proofValueUArr: any;

			try {
				pythiaTransformationKeyPair = createVirgilPythiaTransformationKeyPair(
					transformationKeyPair.privateKey,
					transformationKeyPair.publicKey
				);

				result = pythia.proveSafe(
					transformedPassword,
					blindedPassword,
					transformedTweak,
					pythiaTransformationKeyPair.keyPair
				);

				proofValueCArr = result.proofValueC();
				proofValueUArr = result.proofValueU();

				return {
					proofValueC: wrapper.utils.virgilByteArrayToBuffer(proofValueCArr),
					proofValueU: wrapper.utils.virgilByteArrayToBuffer(proofValueUArr),
				}
			} finally {
				if (process.browser) {
					pythia.delete();
					pythiaTransformationKeyPair && pythiaTransformationKeyPair.freeMem();
					proofValueCArr && proofValueCArr.delete();
					proofValueUArr && proofValueUArr.delete();
					result && result.delete();
				}
			}
		},

		transform (blindedPassword: Buffer, tweak: Buffer, transformationPrivateKey: Buffer) {
			const pythia = createVirgilPythia();
			let result: any;
			let transformedPasswordArr: any;
			let transformedTweakArr: any;

			try {
				result = pythia.transformSafe(
					blindedPassword,
					tweak,
					transformationPrivateKey
				);

				transformedPasswordArr = result.transformedPassword();
				transformedTweakArr = result.transformedTweak();

				return {
					transformedPassword: wrapper.utils.virgilByteArrayToBuffer(transformedPasswordArr),
					transformedTweak: wrapper.utils.virgilByteArrayToBuffer(transformedTweakArr),
				};
			} finally {
				if (process.browser) {
					pythia.delete();
					transformedPasswordArr && transformedPasswordArr.delete();
					transformedTweakArr && transformedTweakArr.delete();
					result && result.delete();
				}
			}
		},

		updateDeblindedWithToken (deblindedPassword: Buffer, passwordUpdateToken: Buffer): Buffer {
			if (deblindedPassword == null) throw new Error('`deblindedPassword` is required');
			if (passwordUpdateToken == null) throw new Error('`passwordUpdateToken` is required');

			const pythia = createVirgilPythia();
			try {
				return pythia.updateDeblindedWithTokenSafe(deblindedPassword, passwordUpdateToken);
			} finally {
				if (process.browser) pythia.delete();
			}
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
			try {
				return pythia.verifySafe(
					transformedPassword,
					blindedPassword,
					tweak,
					transformationPublicKey,
					proofValueC,
					proofValueU
				);
			} finally {
				if (process.browser) pythia.delete();
			}
		}
	}
}
