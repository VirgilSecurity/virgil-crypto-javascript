/**
 * Key used to embed Data Signature into ASN.1 structure.
 * Used in `signThenEncrypt` & `decryptThenVerify`.
 *
 * @hidden
 *
 * @type {string}
 */
export const DATA_SIGNATURE_KEY = 'VIRGIL-DATA-SIGNATURE';

/**
 * Key used to embed signer identifier into ASN.1 structure.
 * Used in signThenEncrypt & decryptThenVerify
 *
 * @hidden
 *
 * @type {string}
 */
export const DATA_SIGNER_ID_KEY = 'VIRGIL-DATA-SIGNER-ID';
