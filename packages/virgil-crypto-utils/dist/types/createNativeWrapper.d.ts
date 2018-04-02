/// <reference types="node" />
export interface WrapperUtils {
    isBuffer(obj: any): boolean;
    bufferToVirgilByteArray(buf: Buffer): any;
    isVirgilByteArray(obj: any): boolean;
    virgilByteArrayToBuffer(arr: any): Buffer;
}
export declare function createNativeWrapper(utils: WrapperUtils): {
    createSafeInstanceMethods: (ctor: Function, methods: string[]) => void;
    createSafeStaticMethods: (ctor: Function & {
        [key: string]: any;
    }, methods: string[]) => void;
};
