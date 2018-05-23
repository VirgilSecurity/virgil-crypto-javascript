/**
 * Key algorithms supported by Virgil Crypto.
 */
export enum KeyPairType {
	/** Ed25519 */
	Default = 'FAST_EC_ED25519',

	/** RSA 2048 bit */
	RSA_2048 = 'RSA_2048',

	/** RSA 3072 bit */
	RSA_3072 = 'RSA_3072',

	/** RSA 4096 bit */
	RSA_4096 = 'RSA_4096',

	/** RSA 8192 bit */
	RSA_8192 = 'RSA_8192',

	/** 256-bits NIST curve */
	EC_SECP256R1 = 'EC_SECP256R1',

	/** 384-bits NIST curve */
	EC_SECP384R1 = 'EC_SECP384R1',

	/** 521-bits NIST curve */
	EC_SECP521R1 = 'EC_SECP521R1',

	/** 256-bits Brainpool curve */
	EC_BP256R1 = 'EC_BP256R1',

	/** 384-bits Brainpool curve */
	EC_BP384R1 = 'EC_BP384R1',

	/** 512-bits Brainpool curve */
	EC_BP512R1 = 'EC_BP512R1',

	/** 256-bits "Koblitz" curve */
	EC_SECP256K1 = 'EC_SECP256K1',

	/** Curve25519 as ECP deprecated format. */
	EC_CURVE25519 = 'EC_CURVE25519',

	/** Curve25519 */
	FAST_EC_X25519 = 'FAST_EC_X25519',

	/** Ed25519 */
	FAST_EC_ED25519 = 'FAST_EC_ED25519'
}
