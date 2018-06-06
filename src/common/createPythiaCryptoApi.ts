import { IVirgilPythiaCryptoApi } from './IVirgilPythiaCryptoApi';
import { createNativeTypeWrapper } from './createNativeTypeWrapper';

export function createPythiaCryptoApi (lib: any): IVirgilPythiaCryptoApi {
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
		blind (password: string | Buffer) {
			if (password == null) throw new Error('`password` is required');

			password = Buffer.isBuffer(password) ? password : Buffer.from(password, 'utf8');
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
			if (transformationKeyId == null) throw new Error('`transformationKeyId` is required');
			if (pythiaSecret == null) throw new Error('`pythiaSecret` is required');
			if (pythiaScopeSecret == null) throw new Error('`pythiaScopeSecret` is required');

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

		deblind (transformedPassword: Buffer, blindingSecret: Buffer) {
			if (transformedPassword == null) throw new Error('`transformedPassword` is required');
			if (blindingSecret == null) throw new Error('`blindingSecret` is required');

			const pythia = createVirgilPythia();
			return pythia.deblindSafe(transformedPassword, blindingSecret);
		},

		getPasswordUpdateToken (oldTransformationPrivateKey: Buffer, newTransformationPrivateKey: Buffer) {
			if (oldTransformationPrivateKey == null)
				throw new Error('`oldTransformationPrivateKey` is required');
			if (newTransformationPrivateKey == null)
				throw new Error('`newTransformationPrivateKey` is required');

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
			if (transformedPassword == null) throw new Error('`transformedPassword` is required');
			if (blindedPassword == null) throw new Error('`blindedPassword` is required');
			if (transformedTweak == null) throw new Error('`transformedTweak` is required');
			if (transformationKeyPair == null) throw new Error('`transformationKeyPair` is required');

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
			if (blindedPassword == null) throw new Error('`blindedPassword` is required');
			if (tweak == null) throw new Error('`tweak` is required');
			if (transformationPrivateKey == null) throw new Error('`transformationPrivateKey` is required');

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

		updateDeblindedWithToken (deblindedPassword: Buffer, passwordUpdateToken: Buffer) {
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
		) {
			if (transformedPassword == null) throw new Error('`transformedPassword` is required');
			if (blindedPassword == null) throw new Error('`blindedPassword` is required');
			if (tweak == null) throw new Error('`tweak` is required');
			if (transformationPublicKey == null) throw new Error('`transformationPublicKey` is required');
			if (proofValueC == null) throw new Error('`proofValueC` is required');
			if (proofValueU == null) throw new Error('`proofValueU` is required');

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
