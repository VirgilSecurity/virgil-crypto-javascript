import { LowLevelPrivateKey, LowLevelPublicKey } from '../types';

export namespace FoundationModules {
  export enum GroupMsgType {
    GROUP_INFO = 0,
    REGULAR = 1
  }

  export class FoundationObject {
    delete(): void;
  }

  export class FoundationObjectWithRng extends FoundationObject {
    set rng(rng: CtrDrbg);
  }

  export class GroupSessionMessage extends FoundationObject {
    getEpoch(): number;
    getSessionId(): Uint8Array;
    serialize(): Uint8Array;
    static deserialize(data: Uint8Array): GroupSessionMessage;
  }

  export class GroupSessionTicket extends FoundationObjectWithRng {
    setupTicketAsNew(sessionId: Uint8Array): void;
    getTicketMessage(): GroupSessionMessage;
  }

  export class GroupSession extends FoundationObjectWithRng {
    addEpoch(message: GroupSessionMessage): void;
    getSessionId(): Uint8Array;
    getCurrentEpoch(): number;
    createGroupTicket(): GroupSessionTicket;
    encrypt(data: Uint8Array, privateKey: LowLevelPrivateKey): GroupSessionMessage;
    decrypt(message: GroupSessionMessage, publicKey: LowLevelPublicKey): Uint8Array;
  }

  export class CtrDrbg extends FoundationObject {
    setupDefaults(): void;
  }

  export class Sha512 extends FoundationObject {
    hash(data: Uint8Array): Uint8Array;
  }
}
