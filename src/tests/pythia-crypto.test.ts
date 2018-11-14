import { VirgilPythiaCrypto } from '../VirgilPythiaCrypto';
import { data } from './data/pythia-crypto-data';

const DEBLINDED_PASSWORD = Buffer.from(data.kDeblindedPassword, 'hex');

const PASSWORD = 'password';
const TRANSFORMATION_KEY_ID = Buffer.from(data.kTransformationKeyID);
const TWEAK = Buffer.from(data.kTweek);
const PYTHIA_SECRET = Buffer.from(data.kPythiaSecret);
const NEW_PYTHIA_SECRET = Buffer.from(data.kNewPythiaSecret);
const PYTHIA_SCOPE_SECRET = Buffer.from(data.kPythiaScopeSecret);

describe('Pythia Crypto', function () {
	this.timeout(10000);
	let pythiaCrypto: VirgilPythiaCrypto;

	beforeEach(function() {
		try {
			pythiaCrypto = new VirgilPythiaCrypto();
		} catch(_) {
			// VirgilPythia is not available on the current platform
			this.skip();
		}
	});

	describe('Deterministic Key Generation', () => {
		it ('computes the transformation key pair deterministically', () => {
			const keyPair = pythiaCrypto.computeTransformationKeyPair({
				transformationKeyId: TRANSFORMATION_KEY_ID,
				pythiaSecret: PYTHIA_SECRET,
				pythiaScopeSecret: PYTHIA_SCOPE_SECRET
			});

			assert.isTrue(keyPair.privateKey.equals(Buffer.from(data.kTransformationPrivateKey, 'hex')));
			assert.isTrue(keyPair.publicKey.equals(Buffer.from(data.kTransformationPublicKey, 'hex')));
		});
	});

	describe('Deblind Stability', () => {
		it ('produces the same result for multiple iterations', () => {
			const iterationsCount = 10;

			for (let i = 0; i < iterationsCount; i += 1) {
				const deblindedPassword = blindEvalDeblind(pythiaCrypto);
				assert.isTrue(
					deblindedPassword.equals(DEBLINDED_PASSWORD),
					'deblined password is equal to pre-computed'
				);
			}
		});
	});

	describe('BlindEvalProveVerify', () => {
		it ('verifies transformed password', () => {

			const { blindedPassword } = pythiaCrypto.blind(PASSWORD);

			const transformationKeyPair = pythiaCrypto.computeTransformationKeyPair({
				transformationKeyId: TRANSFORMATION_KEY_ID,
				pythiaSecret: PYTHIA_SECRET,
				pythiaScopeSecret: PYTHIA_SCOPE_SECRET
			});

			const { transformedPassword, transformedTweak } = pythiaCrypto.transform({
				blindedPassword,
				tweak: TWEAK,
				transformationPrivateKey: transformationKeyPair.privateKey
			});

			const { proofValueC, proofValueU } = pythiaCrypto.prove({
				transformedPassword,
				blindedPassword,
				transformedTweak,
				transformationKeyPair
			});

			const verified = pythiaCrypto.verify({
				transformedPassword,
				blindedPassword,
				proofValueC,
				proofValueU,
				tweak: TWEAK,
				transformationPublicKey: transformationKeyPair.publicKey
			});

			assert.equal(verified, true, 'password is verified');
		});
	});

	describe('Update Delta', () => {
		it ('updates deblinded password with token', () => {
			const { blindingSecret, blindedPassword } = pythiaCrypto.blind(PASSWORD);
			const oldTransformationKeyPair = pythiaCrypto.computeTransformationKeyPair({
				transformationKeyId: TRANSFORMATION_KEY_ID,
				pythiaSecret: PYTHIA_SECRET,
				pythiaScopeSecret: PYTHIA_SCOPE_SECRET
			});
			const { transformedPassword } = pythiaCrypto.transform({
				blindedPassword,
				tweak: TWEAK,
				transformationPrivateKey: oldTransformationKeyPair.privateKey
			});
			const deblindedPassword = pythiaCrypto.deblind({ transformedPassword, blindingSecret });
			const newTransformationKeyPair = pythiaCrypto.computeTransformationKeyPair({
				transformationKeyId: TRANSFORMATION_KEY_ID,
				pythiaSecret: NEW_PYTHIA_SECRET,
				pythiaScopeSecret: PYTHIA_SCOPE_SECRET
			});

			const updateToken = pythiaCrypto.getPasswordUpdateToken({
				oldTransformationPrivateKey: oldTransformationKeyPair.privateKey,
				newTransformationPrivateKey: newTransformationKeyPair.privateKey
			});

			const updatedDeblindedPassword = pythiaCrypto.updateDeblindedWithToken({
				deblindedPassword,
				updateToken
			});
			const {
				blindingSecret: newBlindingSecret,
				blindedPassword: newBlindedPassword
			} = pythiaCrypto.blind(PASSWORD);
			const { transformedPassword: newTransformedPassword } = pythiaCrypto.transform({
				blindedPassword: newBlindedPassword,
				tweak: TWEAK,
				transformationPrivateKey: newTransformationKeyPair.privateKey
			});

			const newDeblindedPassword = pythiaCrypto.deblind({
				transformedPassword: newTransformedPassword,
				blindingSecret: newBlindingSecret
			});
			assert.isTrue(
				updatedDeblindedPassword.equals(newDeblindedPassword),
				'updated password is equal to computed'
			);
		});
	});

	describe('Blind Huge Password', () => {
		it ('throws when given a huge password', () => {
			const hugePassword = Buffer.from('1'.repeat(129));
			assert.throws(() => {
				pythiaCrypto.blind(hugePassword);
			});
		});
	});
});

function blindEvalDeblind(pythiaCrypto: VirgilPythiaCrypto) {
	const { blindingSecret, blindedPassword } = pythiaCrypto.blind(PASSWORD);
	const transformationKeyPair = pythiaCrypto.computeTransformationKeyPair({
		transformationKeyId: TRANSFORMATION_KEY_ID,
		pythiaSecret: PYTHIA_SECRET,
		pythiaScopeSecret: PYTHIA_SCOPE_SECRET
	});
	const { transformedPassword } = pythiaCrypto.transform({
		blindedPassword,
		tweak: TWEAK,
		transformationPrivateKey: transformationKeyPair.privateKey
	});
	return pythiaCrypto.deblind({ transformedPassword, blindingSecret });
}
