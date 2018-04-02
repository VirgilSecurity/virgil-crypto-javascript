export declare class VirgilCryptoError extends Error {
    name: string;
    code?: string;
    constructor(message: string, code?: string, name?: string);
    toString(): string;
}
export declare function errorFromNativeError(err: Error): Error;
export declare function assert(condition: boolean, message: string): void;
