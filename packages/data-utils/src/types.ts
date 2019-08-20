export enum StringEncoding {
  utf8 = 'utf8',
  base64 = 'base64',
  hex = 'hex',
}

export interface StringWithEncoding {
  value: string;
  encoding: keyof typeof StringEncoding;
}

export type Data = Uint8Array | StringWithEncoding | string;
