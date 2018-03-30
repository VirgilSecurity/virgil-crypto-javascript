/// <reference types="node" />
export declare function isBuffer(obj: any): boolean;
export declare function virgilByteArrayToBuffer(byteArray: any): Buffer;
export declare const wrapFunction: (fn: Function, target: any) => (...args: any[]) => any;
