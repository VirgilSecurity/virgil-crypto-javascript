import { pythiaCryptoApi } from '../pythia/node/api';
import { data } from './data/pythia-crypto-data';

const DEBLINDED_PASSWORD = Buffer.from(data.kDeblindedPassword, 'hex');

const PASSWORD = 'password';
const TRANSFORMATION_KEY_ID = Buffer.from(data.kTransformationKeyID);
const TWEAK = Buffer.from(data.kTweek);
const PYTHIA_SECRET = Buffer.from(data.kPythiaSecret);
const NEW_PYTHIA_SECRET = Buffer.from(data.kNewPythiaSecret);
const PYTHIA_SCOPE_SECRET = Buffer.from(data.kPythiaScopeSecret);

const {
	blind,
	computeTransformationKeyPair,
	deblind,
	getPasswordUpdateToken,
	prove,
	transform,
	updateDeblindedWithToken,
	verify
} = pythiaCryptoApi;

function blindEvalDeblind() {
	const { blindingSecret, blindedPassword } = blind(PASSWORD);
	const transformationKeyPair = computeTransformationKeyPair(
		TRANSFORMATION_KEY_ID,
		PYTHIA_SECRET,
		PYTHIA_SCOPE_SECRET
	);
	const { transformedPassword } = transform(blindedPassword, TWEAK, transformationKeyPair.privateKey);
	return deblind(transformedPassword, blindingSecret);
}

describe('Pythia Crypto', function () {
	this.timeout(10000);

	describe('Deterministic Key Generation', () => {
		it ('computes the transformation key pair deterministically', () => {
			const keyPair = computeTransformationKeyPair(
				TRANSFORMATION_KEY_ID,
				PYTHIA_SECRET,
				PYTHIA_SCOPE_SECRET
			);

			assert.isTrue(keyPair.privateKey.equals(Buffer.from(data.kTransformationPrivateKey, 'hex')));
			assert.isTrue(keyPair.publicKey.equals(Buffer.from(data.kTransformationPublicKey, 'hex')));
		});
	});

	describe('Deblind Stability', () => {
		it ('produces the same result for multiple iterations', () => {
			const iterationsCount = 10;

			for (let i = 0; i < iterationsCount; i++) {
				let deblindedPassword = blindEvalDeblind();
				assert.isTrue(deblindedPassword.equals(DEBLINDED_PASSWORD), 'deblined password is equal to pre-computed');
			}
		});
	});

	describe('BlindEvalProveVerify', () => {
		it ('verifies transformed password', () => {

			const { blindedPassword } = blind(PASSWORD);

			const transformationKeyPair = computeTransformationKeyPair(
				TRANSFORMATION_KEY_ID,
				PYTHIA_SECRET,
				PYTHIA_SCOPE_SECRET
			);

			const { transformedPassword, transformedTweak } = transform(
				blindedPassword,
				TWEAK,
				transformationKeyPair.privateKey
			);

			const { proofValueC, proofValueU } = prove(
				transformedPassword,
				blindedPassword,
				transformedTweak,
				transformationKeyPair
			);

			const verified = verify(
				transformedPassword,
				blindedPassword,
				TWEAK,
				transformationKeyPair.publicKey,
				proofValueC,
				proofValueU
			);

			assert.equal(verified, true, 'password is verified');
		});
	});

	describe('Update Delta', () => {
		it ('updates deblinded password with token', () => {
			const { blindingSecret, blindedPassword } = blind(PASSWORD);
			const oldTransformationKeyPair = computeTransformationKeyPair(
				TRANSFORMATION_KEY_ID,
				PYTHIA_SECRET,
				PYTHIA_SCOPE_SECRET
			);
			const { transformedPassword } = transform(
				blindedPassword,
				TWEAK,
				oldTransformationKeyPair.privateKey
			);
			const deblindedPassword = deblind(transformedPassword, blindingSecret);
			const newTransformationKeyPair = computeTransformationKeyPair(
				TRANSFORMATION_KEY_ID,
				NEW_PYTHIA_SECRET,
				PYTHIA_SCOPE_SECRET
			);

			const updateToken = getPasswordUpdateToken(
				oldTransformationKeyPair.privateKey,
				newTransformationKeyPair.privateKey
			);

			const updatedDeblindedPassword = updateDeblindedWithToken(deblindedPassword, updateToken);
			const { blindingSecret: newBlindingSecret, blindedPassword: newBlindedPassword } = blind(PASSWORD);
			const { transformedPassword: newTransformedPassword } = transform(
				newBlindedPassword,
				TWEAK,
				newTransformationKeyPair.privateKey
			);

			const newDeblindedPassword = deblind(newTransformedPassword, newBlindingSecret);
			assert.isTrue(updatedDeblindedPassword.equals(newDeblindedPassword), 'updated password is equal to computed');
		});
	});

	describe('Blind Huge Password', () => {
		it ('throws when given a huge password', () => {
			const hugePassword = '1'.repeat(129);
			assert.throws(() => {
				blind(hugePassword);
			});
		});
	});
});
