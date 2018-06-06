import { pythiaCryptoApi } from './pythia/node/api';
import { BlindResult, ProveResult, TransformationKeyPair, TransformResult } from './common';

export interface ComputeTransformationKeyPairParams {
	transformationKeyId: Buffer;
	pythiaSecret: Buffer;
	pythiaScopeSecret: Buffer;
}

export interface DeblindParams {
	transformedPassword: Buffer;
	blindingSecret: Buffer;
}

export interface GetPasswordUpdateTokenParams {
	oldTransformationPrivateKey: Buffer;
	newTransformationPrivateKey: Buffer;
}

export interface ProveParams {
	transformedPassword: Buffer;
	blindedPassword: Buffer;
	transformedTweak: Buffer;
	transformationKeyPair: TransformationKeyPair;
}

export interface TransformParams {
	blindedPassword: Buffer;
	tweak: Buffer;
	transformationPrivateKey: Buffer;
}

export interface UpdateDeblindedWithTokenParams {
	deblindedPassword: Buffer;
	updateToken: Buffer;
}

export interface VerifyParams {
	transformedPassword: Buffer;
	blindedPassword: Buffer;
	tweak: Buffer;
	transformationPublicKey: Buffer;
	proofValueC: Buffer;
	proofValueU: Buffer;
}

export class VirgilPythia {
	blind (password: string | Buffer): BlindResult {
		return pythiaCryptoApi.blind(password);
	}

	computeTransformationKeyPair (
		{ transformationKeyId, pythiaSecret, pythiaScopeSecret }: ComputeTransformationKeyPairParams
	): TransformationKeyPair {
		return pythiaCryptoApi.computeTransformationKeyPair(
			transformationKeyId, pythiaSecret, pythiaScopeSecret
		);
	}

	deblind ({ transformedPassword, blindingSecret }: DeblindParams) {
		return pythiaCryptoApi.deblind(transformedPassword, blindingSecret);
	}

	getPasswordUpdateToken (
		{ oldTransformationPrivateKey, newTransformationPrivateKey }: GetPasswordUpdateTokenParams
	) {
		return pythiaCryptoApi.getPasswordUpdateToken(oldTransformationPrivateKey, newTransformationPrivateKey);
	}

	prove (
		{ transformedPassword, blindedPassword, transformedTweak, transformationKeyPair }: ProveParams
	): ProveResult {
		return pythiaCryptoApi.prove(transformedPassword, blindedPassword, transformedTweak, transformationKeyPair);
	}

	transform ({ blindedPassword, tweak, transformationPrivateKey }: TransformParams): TransformResult {
		return pythiaCryptoApi.transform(blindedPassword, tweak, transformationPrivateKey);
	}

	updateDeblindedWithToken ({ deblindedPassword, updateToken }: UpdateDeblindedWithTokenParams) {
		return pythiaCryptoApi.updateDeblindedWithToken(deblindedPassword, updateToken);
	}

	verify ({
		transformedPassword,
		blindedPassword,
		tweak,
		transformationPublicKey,
		proofValueC,
		proofValueU
	}: VerifyParams) {
		return pythiaCryptoApi.verify(
			transformedPassword,
			blindedPassword,
			tweak,
			transformationPublicKey,
			proofValueC,
			proofValueU
		);
	}
}
