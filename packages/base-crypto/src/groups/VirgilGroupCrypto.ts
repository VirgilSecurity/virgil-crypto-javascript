import { FoundationModules } from './foundation-types';
import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getFoundationModules } from '../foundationModules';
import { getLowLevelPrivateKey } from '../privateKeyUtils';
import { Data } from '../types';
import { validatePrivateKey, validatePublicKey } from '../validators';
import { VirgilPrivateKey } from '../VirgilPrivateKey';
import { VirgilPublicKey } from '../VirgilPublicKey';

const MIN_GROUP_ID_BYTE_LENGTH = 10;

let foundationModules: typeof FoundationModules;
let random: FoundationModules.CtrDrbg;

export class VirgilGroupTicket {
  private serializedGroupMessage: Uint8Array;

  constructor(groupMessage: Uint8Array) {
    this.serializedGroupMessage = groupMessage;
  }

  getGroupSessionMessage() {
    return foundationModules.GroupSessionMessage.deserialize(this.serializedGroupMessage);
  }
}

export class VirgilGroup {
  private tickets: VirgilGroupTicket[];

  constructor(tickets: VirgilGroupTicket[]) {
    this.tickets = tickets;
  }

  encrypt(data: Data, signingPrivateKey: VirgilPrivateKey) {
    const dataBytes = dataToUint8Array(data, 'utf8');
    validatePrivateKey(signingPrivateKey);
    const session = this.createSession();
    const lowLevelPrivateKey = getLowLevelPrivateKey(signingPrivateKey);

    try {
      const message = session.encrypt(dataBytes, lowLevelPrivateKey);
      const result = toBuffer(message.serialize());
      message.delete();
      return result;
    } finally {
      // TODO uncomment when keys are stored serialized
      // lowLevelPrivateKey.delete();
      session.delete();
    }
  }

  decrypt(encryptedData: Data, verifyingPublicKey: VirgilPublicKey) {
    const encryptedDataBytes = dataToUint8Array(encryptedData, 'base64');
    validatePublicKey(verifyingPublicKey);
    const session = this.createSession();
    const lowLevelPublicKey = verifyingPublicKey.key;
    let message: FoundationModules.GroupSessionMessage|undefined;

    try {
      message = foundationModules.GroupSessionMessage.deserialize(encryptedDataBytes);
      return toBuffer(session.decrypt(message, lowLevelPublicKey));
    } finally {
      message && message.delete;
      // TODO uncomment when keys are stored serialized
      // lowLevelPublicKey.delete();
      session.delete();
    }
  }

  addNewTicket() {
    const session = this.createSession();
    try {
      const ticket = session.createGroupTicket();
      const message = ticket.getTicketMessage();
      ticket.delete();
      session.addEpoch(message);
      this.tickets.push(new VirgilGroupTicket(message.serialize()));
      message.delete();
    } finally {
      session.delete();
    }
  }

  private createSession() {
    const session = new foundationModules.GroupSession();
    session.rng = random;

    let deleteQueue: FoundationModules.FoundationObject[] = [];
    try {
      for (let ticket of this.tickets) {
        const ticketMessage = ticket.getGroupSessionMessage();
        deleteQueue.push(ticketMessage);

        session.addEpoch(ticketMessage);
      }
      return session;
    } finally {
      while(deleteQueue.length) {
        deleteQueue.pop()!.delete();
      };
    }
  }
}

export class VirgilGroupCrypto {
  constructor() {
    if (!foundationModules) {
      foundationModules = getFoundationModules();
    }
    if (!random) {
      random = new foundationModules.CtrDrbg();
      random.setupDefaults();
    }
  }

  createGroup(groupId: Data) {
    const sessionId = this.computeSessionId(groupId);
    const setupMessage = this.createSetupTicketMessage(sessionId);

    const ticket = new VirgilGroupTicket(setupMessage.serialize());
    setupMessage.delete();
    return new VirgilGroup([ticket]);
  }

  private computeSessionId(groupId: Data) {
    const groupIdBytes = dataToUint8Array(groupId, 'utf8');
    if (groupIdBytes.byteLength < MIN_GROUP_ID_BYTE_LENGTH) {
      throw new Error(`Group Id too short. Must be at least ${MIN_GROUP_ID_BYTE_LENGTH} bytes`);
    }

    const sha512 = new foundationModules.Sha512();
    try {
      return sha512.hash(groupIdBytes).subarray(0, 32);
    } finally {
      sha512.delete();
    }
  }

  private createSetupTicketMessage(sessionId: Uint8Array) {
    const ticket = new foundationModules.GroupSessionTicket();
    ticket.rng = random;
    try {
      ticket.setupTicketAsNew(sessionId);
      return ticket.getTicketMessage();
    } finally {
      ticket.delete();
    }
  }
}

