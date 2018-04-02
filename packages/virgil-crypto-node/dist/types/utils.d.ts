/// <reference path="../../src/declarations.d.ts" />
/// <reference types="node" />
export declare function isBuffer(obj: any): boolean;
export declare function virgilByteArrayToBuffer(byteArray: any): Buffer;
export declare const wrapper: {
    wrapFunction: Function;
    wrapInstanceMethods: (ctor: Function, methods: string[]) => void;
    wrapStaticMethods: (ctor: any, methods: string[]) => void;
};
