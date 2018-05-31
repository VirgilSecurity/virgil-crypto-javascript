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

	wrapper.createSafeInstanceMethods(
		lib.VirgilPythiaBlindResult,
		[ 'blindedPassword', 'blindingSecret' ]
	);

	wrapper.createSafeInstanceMethods(
		lib.VirgilPythiaProveResult,
		[ 'proofValueC', 'proofValueU' ]
	);

	wrapper.createSafeInstanceMethods(
		lib.VirgilPythiaTransformationKeyPair,
		[ 'privateKey', 'publicKey' ]
	);

	wrapper.createSafeInstanceMethods(
		lib.VirgilPythiaTransformResult,
		[ 'transformedPassword', 'transformedTweak' ]
	);

	lib.createVirgilPythia = () => {
		const pythia = new lib.VirgilPythia();
		if (process.browser) pythia.deleteLater();
		return pythia;
	};

	lib.createVirgilRandom = () => {
		const random = new lib.VirgilRandom('');
		if (process.browser) random.deleteLater();
		return random;
	};

	lib.getRandomBytes = (numOfBytes: number) => {
		if (process.browser) {
			const personalInfo = lib.VirgilByteArrayUtils.stringToBytes('');
			const random = new lib.VirgilRandom(personalInfo);

			let byteArr: any;
			try {
				byteArr = random.randomizeBytes(numOfBytes);
				return wrapper.utils.virgilByteArrayToBuffer(byteArr);
			} finally {
				personalInfo.delete();
				random.delete();
				byteArr && byteArr.delete();
			}
		} else {
			const random = new lib.VirgilRandom('');
			return wrapper.utils.virgilByteArrayToBuffer(random.randomize(numOfBytes));
		}
	};

	lib.createVirgilPythiaTransformationKeyPair = (privateKey: Buffer, publicKey: Buffer) => {
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
			const pythia = lib.createVirgilPythia();

			const result = pythia.blindSafe(password);
			return {
				blindedPassword: result.blindedPasswordSafe(),
				blindingSecret: result.blindingSecretSafe()
			};
		},

		computeTransformationKeyPair (transformationKeyId: Buffer, pythiaSecret: Buffer, pythiaScopeSecret: Buffer) {
			if (transformationKeyId == null) throw new Error('`transformationKeyId` is required');
			if (pythiaSecret == null) throw new Error('`pythiaSecret` is required');
			if (pythiaScopeSecret == null) throw new Error('`pythiaScopeSecret` is required');

			const pythia = lib.createVirgilPythia();
			const keyPair = pythia.computeTransformationKeyPairSafe(
				transformationKeyId,
				pythiaSecret,
				pythiaScopeSecret
			);

			return {
				privateKey: keyPair.privateKeySafe(),
				publicKey: keyPair.publicKeySafe()
			};
		},

		deblind (transformedPassword: Buffer, blindingSecret: Buffer) {
			if (transformedPassword == null) throw new Error('`transformedPassword` is required');
			if (blindingSecret == null) throw new Error('`blindingSecret` is required');

			const pythia = lib.createVirgilPythia();
			return pythia.deblindSafe(transformedPassword, blindingSecret);
		},

		generateSalt (numOfBytes: number = 32) {
			return lib.getRandomBytes(numOfBytes);
		},

		getPasswordUpdateToken (oldTransformationPrivateKey: Buffer, newTransformationPrivateKey: Buffer) {
			if (oldTransformationPrivateKey == null)
				throw new Error('`oldTransformationPrivateKey` is required');
			if (newTransformationPrivateKey == null)
				throw new Error('`newTransformationPrivateKey` is required');

			const pythia = lib.createVirgilPythia();
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

			transformationKeyPair = lib.createVirgilPythiaTransformationKeyPair(
				transformationKeyPair.privateKey,
				transformationKeyPair.publicKey
			);

			const pythia = lib.createVirgilPythia();
			const result = pythia.proveSafe(
				transformedPassword,
				blindedPassword,
				transformedTweak,
				transformationKeyPair
			);

			return {
				proofValueC: result.proofValueCSafe(),
				proofValueU: result.proofValueUSafe(),
			}
		},

		transform (blindedPassword: Buffer, tweak: Buffer, transformationPrivateKey: Buffer) {
			if (blindedPassword == null) throw new Error('`blindedPassword` is required');
			if (tweak == null) throw new Error('`tweak` is required');
			if (transformationPrivateKey == null) throw new Error('`transformationPrivateKey` is required');

			const pythia = lib.createVirgilPythia();
			const result = pythia.transformSafe(
				blindedPassword,
				tweak,
				transformationPrivateKey
			);

			return {
				transformedPassword: result.transformedPasswordSafe(),
				transformedTweak: result.transformedTweakSafe(),
			};
		},

		updateDeblindedWithToken (deblindedPassword: Buffer, passwordUpdateToken: Buffer) {
			if (deblindedPassword == null) throw new Error('`deblindedPassword` is required');
			if (passwordUpdateToken == null) throw new Error('`passwordUpdateToken` is required');

			const pythia = lib.createVirgilPythia();
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

			const pythia = lib.createVirgilPythia();
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
