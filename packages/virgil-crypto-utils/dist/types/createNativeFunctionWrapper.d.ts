/// <reference path="../../src/declarations.d.ts" />
/// <reference types="node" />
export interface WrapperUtils {
    isBuffer(obj: any): boolean;
    bufferToVirgilByteArray(buf: Buffer): any;
    isVirgilByteArray(obj: any): boolean;
    virgilByteArrayToBuffer(arr: any): Buffer;
}
export declare function createNativeFunctionWrapper(utils: WrapperUtils): (fn: Function, target: any) => (...args: any[]) => any;
