export enum VirgilCryptoErrorStatus {
  STREAM_ILLEGAL_STATE = 'STREAM_ILLEGAL_STATE',
  DATA_NOT_SIGNED = 'DATA_NOT_SIGNED',
  SIGNER_NOT_FOUND = 'SIGNER_NOT_FOUND',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
}

export class VirgilCryptoError extends Error {
  static readonly DEFAULT_MESSAGE =
    "Use the 'status' property and 'VirgilCryptoErrorStatus' enum to check for specific error.";

  readonly status: VirgilCryptoErrorStatus;

  constructor(errorStatus: VirgilCryptoErrorStatus, message?: string) {
    super(message || VirgilCryptoError.DEFAULT_MESSAGE);
    Object.setPrototypeOf(this, VirgilCryptoError.prototype);
    this.name = 'VirgilCryptoError';
    this.status = errorStatus;
  }
}
