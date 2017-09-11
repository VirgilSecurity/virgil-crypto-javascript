import VirgilPFS from '../pfs/VirgilPFS';

const initiatorIdentityPrivateKey = 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tC' +
	'k1DNENBUUF3QlFZREsyVndCQ0lFSUZ3Mkx5N1NZSGFuYkNqeHd4N3dtMXlMTFpUbXpOcD' +
	'dNMHZXZ0lKTU1hcVkKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=';
const initiatorIdentityPublicKey = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTU' +
	'Nvd0JRWURLMlZ3QXlFQXpCNDVwZnJCWXFIdW9IWHpTV01FM1dwMlNpNXgzTStiSklsZWl' +
	'TUEV4MW89Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=';

const initiatorEphemeralPrivateKey = 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t' +
	'Ck1DNENBUUF3QlFZREsyVndCQ0lFSU5Rb3ZzUHJpN1dsQWtXdy9OUVhRMkRrVkhmYWgyT' +
	'lg4Sjc4RDVObGZkeS8KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=';
const initiatorEphemeralPublicKey = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KT' +
	'UNvd0JRWURLMlZ3QXlFQStwNXJ4cURDemlyeHdLQWZqN0JNaVF0RkFOSUZhR3NhenU3dk' +
	'VhU21oa3M9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=';

const responderIdentityPrivateKey = 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tC' +
	'k1DNENBUUF3QlFZREsyVndCQ0lFSUp1eXgxWU5yN0o4YTVLQlNDNUtvYkxsSkl0bEZFbD' +
	'JGN2lCZUxFVjNZWU4KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=';
const responderIdentityPublicKey = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTU' +
	'Nvd0JRWURLMlZ3QXlFQW4veTJVU243Uy9Wb2hsZmROUWMyUUFhc2JlV1hOTGErVng2R1h' +
	'VckhPOHM9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=';

const responderLongTermPrivateKey = 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tC' +
	'k1DNENBUUF3QlFZREsyVndCQ0lFSUJ0bWtVQ1Qwc2JnV1Yvb2xnRDdjbnZlTVlrcGJrYz' +
	'hsSmxQeDRyY0Z4QmEKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=';
const responderLongTermPublicKey = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTU' +
	'Nvd0JRWURLMlZ3QXlFQXhBWlI1bExkM2ZXL2c0THdCbHc3OE1NWTRtTG92TmZoVVdYd0l' +
	'ZdkRhclE9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=';

const responderOneTimePrivateKey = 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk' +
	'1DNENBUUF3QlFZREsyVndCQ0lFSUhnZVh0dFE5bDllc2dyNlI2TEVkZDc0TFRIVHFscVV' +
	'XM01icEM3cVBPVXkKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=';
const responderOneTimePublicKey = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUN' +
	'vd0JRWURLMlZ3QXlFQTAxSjVTWHduU2FXUUU0TnVoWWIyRlFKVzQ3SVZESHUrMkNsTGFo' +
	'ZFFWUGc9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=';

const getInitiatorPrivateInfo = () => ({
	identityPrivateKey: Buffer.from(initiatorIdentityPrivateKey, 'base64'),
	ephemeralPrivateKey: Buffer.from(initiatorEphemeralPrivateKey, 'base64')
});

const getInitiatorPublicInfo = () => ({
	identityPublicKey: Buffer.from(initiatorIdentityPublicKey, 'base64'),
	ephemeralPublicKey: Buffer.from(initiatorEphemeralPublicKey, 'base64')
});

const getResponderPrivateInfo = () => ({
	identityPrivateKey: Buffer.from(responderIdentityPrivateKey, 'base64'),
	longTermPrivateKey: Buffer.from(responderLongTermPrivateKey, 'base64')
});

const getResponderPrivateInfoWithOTK = () => ({
	identityPrivateKey: Buffer.from(responderIdentityPrivateKey, 'base64'),
	longTermPrivateKey: Buffer.from(responderLongTermPrivateKey, 'base64'),
	oneTimePrivateKey: Buffer.from(responderOneTimePrivateKey, 'base64')
});

const getResponderPublicInfo = () => ({
	identityPublicKey: Buffer.from(responderIdentityPublicKey, 'base64'),
	longTermPublicKey: Buffer.from(responderLongTermPublicKey, 'base64'),
});

const getResponderPublicInfoWithOTK = () => ({
	identityPublicKey: Buffer.from(responderIdentityPublicKey, 'base64'),
	longTermPublicKey: Buffer.from(responderLongTermPublicKey, 'base64'),
	oneTimePublicKey: Buffer.from(responderOneTimePublicKey, 'base64')
});

describe('VirgilPFS', function() {

	it('getSessionId() returns null when no session started', function () {
		const pfs = new VirgilPFS();
		expect(pfs.getSessionId()).toBeNull();
	});

	it('creates initiator session without OTK', function () {
		const pfs = new VirgilPFS();
		pfs.startInitiatorSession({
			initiatorPrivateInfo: getInitiatorPrivateInfo(),
			responderPublicInfo: getResponderPublicInfo()
		});

		expect(pfs.getSessionId()).not.toBeNull();
	});

	it('creates initiator session with OTK', function () {
		const pfs = new VirgilPFS();
		pfs.startInitiatorSession({
			initiatorPrivateInfo: getInitiatorPrivateInfo(),
			responderPublicInfo: getResponderPublicInfoWithOTK()
		});

		expect(pfs.getSessionId()).not.toBeNull();
	});

	it('creates responder session without OTK', function () {
		const pfs = new VirgilPFS();
		pfs.startResponderSession({
			responderPrivateInfo: getResponderPrivateInfo(),
			initiatorPublicInfo: getInitiatorPublicInfo()
		});

		expect(pfs.getSessionId()).not.toBeNull();
	});

	it('creates responder session with OTK', function () {
		const pfs = new VirgilPFS();
		pfs.startResponderSession({
			responderPrivateInfo: getResponderPrivateInfoWithOTK(),
			initiatorPublicInfo: getInitiatorPublicInfo()
		});

		expect(pfs.getSessionId()).not.toBeNull();
	});

	it('getSession() returns null when no session started', function () {
		const pfs = new VirgilPFS();
		expect(pfs.getSession()).toBeNull();
	});

	it('getSession() returns valid initiator session', function () {
		const pfs = new VirgilPFS();
		pfs.startInitiatorSession({
			initiatorPrivateInfo: getInitiatorPrivateInfo(),
			responderPublicInfo: getResponderPublicInfoWithOTK()
		});

		const session = pfs.getSession();
		expect(session.id).toEqual(jasmine.any(Buffer));
		expect(session.encryptionSecretKey).toEqual(jasmine.any(Buffer));
		expect(session.decryptionSecretKey).toEqual(jasmine.any(Buffer));
		expect(session.additionalData).toEqual(jasmine.any(Buffer));

		expect(session.id.length).toBeGreaterThan(0);
		expect(session.encryptionSecretKey.length).toBeGreaterThan(0);
		expect(session.decryptionSecretKey.length).toBeGreaterThan(0);

		// additional data is initialized even if not passed by the client
		expect(session.additionalData.length).toBeGreaterThan(0);
	});

	it('getSession() returns valid responder session', function () {
		const pfs = new VirgilPFS();
		const data = Buffer.from('addition');

		pfs.startResponderSession({
			responderPrivateInfo: getResponderPrivateInfoWithOTK(),
			initiatorPublicInfo: getInitiatorPublicInfo()
		});

		const session = pfs.getSession();
		expect(session.id).toEqual(jasmine.any(Buffer));
		expect(session.encryptionSecretKey).toEqual(jasmine.any(Buffer));
		expect(session.decryptionSecretKey).toEqual(jasmine.any(Buffer));
		expect(session.additionalData).toEqual(jasmine.any(Buffer));

		expect(session.id.length).toBeGreaterThan(0);
		expect(session.encryptionSecretKey.length).toBeGreaterThan(0);
		expect(session.decryptionSecretKey.length).toBeGreaterThan(0);

		// additional data is not the same the client passes in
		expect(session.additionalData.equals(data)).toBeFalse();
	});

	it('sets initiator session', function () {
		const pfs = new VirgilPFS();
		pfs.startInitiatorSession({
			initiatorPrivateInfo: getInitiatorPrivateInfo(),
			responderPublicInfo: getResponderPublicInfoWithOTK()
		});

		const session = pfs.getSession();
		pfs.destroy();

		const newPfs = new VirgilPFS();
		expect(newPfs.getSessionId()).toBeNull();
		newPfs.setSession(session);
		expect(newPfs.getSessionId().equals(session.id)).toBeTrue();
	});

	it('sets responder session', function () {
		const pfs = new VirgilPFS();

		pfs.startResponderSession({
			responderPrivateInfo: getResponderPrivateInfoWithOTK(),
			initiatorPublicInfo: getInitiatorPublicInfo()
		});

		const session = pfs.getSession();
		pfs.destroy();

		const newPfs = new VirgilPFS();
		expect(newPfs.getSessionId()).toBeNull();
		newPfs.setSession(session);
		expect(newPfs.getSessionId().equals(session.id)).toBeTrue();
	});

	it('encrypts message with initiator session', function() {
		const pfs = new VirgilPFS();
		pfs.startInitiatorSession({
			initiatorPrivateInfo: getInitiatorPrivateInfo(),
			responderPublicInfo: getResponderPublicInfoWithOTK()
		});

		const message = Buffer.from('Secret message');
		const encryptedMessage = pfs.encrypt(message);

		expect(encryptedMessage).toEqual(jasmine.objectContaining({
			sessionId: jasmine.any(Buffer),
			salt: jasmine.any(Buffer),
			ciphertext: jasmine.any(Buffer)
		}));
		expect(encryptedMessage.sessionId.length).toBeGreaterThan(0);
		expect(encryptedMessage.salt.length).toBeGreaterThan(0);
		expect(encryptedMessage.ciphertext.length).toBeGreaterThan(0);
	});

	it('encrypts message with responder session', function() {
		const pfs = new VirgilPFS();
		pfs.startResponderSession({
			responderPrivateInfo: getResponderPrivateInfo(),
			initiatorPublicInfo: getInitiatorPublicInfo()
		});

		const message = Buffer.from('Secret message');
		const encryptedMessage = pfs.encrypt(message);

		expect(encryptedMessage).toEqual(jasmine.objectContaining({
			sessionId: jasmine.any(Buffer),
			salt: jasmine.any(Buffer),
			ciphertext: jasmine.any(Buffer)
		}));
		expect(encryptedMessage.sessionId.length).toBeGreaterThan(0);
		expect(encryptedMessage.salt.length).toBeGreaterThan(0);
		expect(encryptedMessage.ciphertext.length).toBeGreaterThan(0);
	});

	it('decrypts message with responder session without OTK', function () {
		function encrypt(message) {
			const pfs = new VirgilPFS();
			pfs.startInitiatorSession({
				initiatorPrivateInfo: getInitiatorPrivateInfo(),
				responderPublicInfo: getResponderPublicInfo()
			});

			return pfs.encrypt(message);
		}

		function decrypt(encryptedMessage) {
			const pfs = new VirgilPFS();
			pfs.startResponderSession({
				responderPrivateInfo: getResponderPrivateInfo(),
				initiatorPublicInfo: getInitiatorPublicInfo()
			});

			return pfs.decrypt(encryptedMessage);
		}

		const message = Buffer.from('Secret message');
		const encryptedMessage = encrypt(message);
		const decryptedMessage = decrypt(encryptedMessage);

		expect(decryptedMessage.toString()).toEqual('Secret message');
	});

	it('decrypts message with initiator session without OTK', function () {
		function encrypt(message) {
			const pfs = new VirgilPFS();
			pfs.startResponderSession({
				responderPrivateInfo: getResponderPrivateInfo(),
				initiatorPublicInfo: getInitiatorPublicInfo()
			});

			return pfs.encrypt(message);
		}

		function decrypt(encryptedMessage) {
			const pfs = new VirgilPFS();
			pfs.startInitiatorSession({
				initiatorPrivateInfo: getInitiatorPrivateInfo(),
				responderPublicInfo: getResponderPublicInfo()
			});

			return pfs.decrypt(encryptedMessage);
		}

		const message = Buffer.from('Secret message');
		const encryptedMessage = encrypt(message);
		const decryptedMessage = decrypt(encryptedMessage);

		expect(decryptedMessage.toString()).toEqual('Secret message');
	});

	it('decrypts message with responder session with OTK', function () {
		function encrypt(message) {
			const pfs = new VirgilPFS();
			pfs.startInitiatorSession({
				initiatorPrivateInfo: getInitiatorPrivateInfo(),
				responderPublicInfo: getResponderPublicInfoWithOTK()
			});

			return pfs.encrypt(message);
		}

		function decrypt(encryptedMessage) {
			const pfs = new VirgilPFS();
			pfs.startResponderSession({
				responderPrivateInfo: getResponderPrivateInfoWithOTK(),
				initiatorPublicInfo: getInitiatorPublicInfo()
			});

			return pfs.decrypt(encryptedMessage);
		}

		const message = Buffer.from('Secret message');
		const encryptedMessage = encrypt(message);
		const decryptedMessage = decrypt(encryptedMessage);

		expect(decryptedMessage.toString()).toEqual('Secret message');
	});

	it('decrypts message with initiator session with OTK', function () {
		function encrypt(message) {
			const pfs = new VirgilPFS();
			pfs.startResponderSession({
				responderPrivateInfo: getResponderPrivateInfoWithOTK(),
				initiatorPublicInfo: getInitiatorPublicInfo()
			});

			return pfs.encrypt(message);
		}

		function decrypt(encryptedMessage) {
			const pfs = new VirgilPFS();
			pfs.startInitiatorSession({
				initiatorPrivateInfo: getInitiatorPrivateInfo(),
				responderPublicInfo: getResponderPublicInfoWithOTK()
			});

			return pfs.decrypt(encryptedMessage);
		}

		const message = Buffer.from('Secret message');
		const encryptedMessage = encrypt(message);
		const decryptedMessage = decrypt(encryptedMessage);

		expect(decryptedMessage.toString()).toEqual('Secret message');
	});
});
