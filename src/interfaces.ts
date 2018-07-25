/**
 * Interface for objects that represent a private key in cryptographic operations.
 *
 * Matches the `IPrivateKey` interface from {@link https://bit.ly/2IYRPme|virgil-sdk}.
 */
export interface IPrivateKey {}

/**
 * Interface for objects represent a public key in cryptographic operations.
 *
 * Matches the `IPublicKey` interface from {@link https://bit.ly/2rWQBy0|virgil-sdk}.
 */
export interface IPublicKey {}

/**
 * Represents input bytes as either a string, Buffer or ArrayBuffer.
 * If data is a string - assumed encoding depends on the method the input is being
 * passed to.
 *
 * If data is Buffer, it is used as is, without copying.
 *
 * If data is ArrayBuffer, the view of the ArrayBuffer will be created without copying the
 * underlying memory.
 */
export type Data = string|Buffer|ArrayBuffer;
