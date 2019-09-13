import { FoundationModules } from './foundation-types';
import { dataToUint8Array, toBuffer } from '@virgilsecurity/data-utils';

import { getFoundationModules } from '../foundationModules';
import { getLowLevelPrivateKey } from '../privateKeyUtils';
import { Data } from '../types';
import { validatePrivateKey, validatePublicKey } from '../validators';
import { VirgilPrivateKey } from '../VirgilPrivateKey';
import { VirgilPublicKey } from '../VirgilPublicKey';
import { NodeBuffer } from '@virgilsecurity/crypto-types';

const MIN_GROUP_ID_BYTE_LENGTH = 10;

let foundationModules: typeof FoundationModules;
let random: FoundationModules.CtrDrbg;

export interface IVirgilGroupSession {
  getSessionId(): string;
  getCurrentEpochNumber(): number;
  encrypt(data: Data, signingPrivateKey: VirgilPrivateKey): NodeBuffer;
  decrypt(encryptedData: Data, verifyingPublicKey: VirgilPublicKey): NodeBuffer;
  addNewEpoch(): NodeBuffer;
  export(): NodeBuffer[];
}

function getEpochNumberFromEpochMessage(epochMessage: Uint8Array) {
  const epoch = foundationModules.GroupSessionMessage.deserialize(epochMessage);
  const epochNumber = epoch.getEpoch();
  epoch.delete();
  return epochNumber;
}

function createLowLevelSession(epochMessages: Uint8Array[]) {
  const session = new foundationModules.GroupSession();
  session.rng = random;

  let deleteQueue: FoundationModules.FoundationObject[] = [];
  try {
    for (let epochMessage of epochMessages) {
      const epoch = foundationModules.GroupSessionMessage.deserialize(epochMessage);
      deleteQueue.push(epoch);
      session.addEpoch(epoch);
    }
    return session;
  } finally {
    while(deleteQueue.length) {
      deleteQueue.pop()!.delete();
    };
  }
}

function createVirgilGroupSession(epochMessages: Uint8Array[]): IVirgilGroupSession {
  epochMessages = epochMessages
    .slice()
    .sort((a, b) => getEpochNumberFromEpochMessage(a) - getEpochNumberFromEpochMessage(b));

  return {
    getSessionId() {
      const session = createLowLevelSession(epochMessages);
      const id = session.getSessionId();
      session.delete();
      return toBuffer(id).toString('hex');
    },

    getCurrentEpochNumber() {
      return getEpochNumberFromEpochMessage(epochMessages[epochMessages.length - 1]);
    },

    encrypt(data: Data, signingPrivateKey: VirgilPrivateKey) {
      const dataBytes = dataToUint8Array(data, 'utf8');
      validatePrivateKey(signingPrivateKey);
      const session = createLowLevelSession(epochMessages);
      const lowLevelPrivateKey = getLowLevelPrivateKey(signingPrivateKey);

      try {
        const message = session.encrypt(dataBytes, lowLevelPrivateKey);
        const encrypted = message.serialize();
        message.delete();
        return toBuffer(encrypted);
      } finally {
        // TODO uncomment when keys are stored serialized
        // lowLevelPrivateKey.delete();
        session.delete();
      }
    },

    decrypt(encryptedData: Data, verifyingPublicKey: VirgilPublicKey) {
      const encryptedDataBytes = dataToUint8Array(encryptedData, 'base64');
      validatePublicKey(verifyingPublicKey);
      const session = createLowLevelSession(epochMessages);
      const lowLevelPublicKey = verifyingPublicKey.key;
      let message: FoundationModules.GroupSessionMessage|undefined;

      try {
        message = foundationModules.GroupSessionMessage.deserialize(encryptedDataBytes);
        return toBuffer(session.decrypt(message, lowLevelPublicKey));
      } finally {
        message && message.delete();
        // TODO uncomment when keys are stored serialized
        // lowLevelPublicKey.delete();
        session.delete();
      }
    },

    addNewEpoch() {
      const session = createLowLevelSession(epochMessages);
      try {
        const newEpochTicket = session.createGroupTicket();
        const newEpoch = newEpochTicket.getTicketMessage();
        const newEpochMessage = newEpoch.serialize();

        epochMessages.push(newEpochMessage);

        newEpoch.delete();
        newEpochTicket.delete();

        return toBuffer(newEpochMessage);
      } finally {
        session.delete();
      }
    },

    export() {
      return epochMessages.map(toBuffer);
    }
  }
}

export function generateGroupSession(groupId: Data) {
  ensureModulesLoaded();
  const groupIdBytes = dataToUint8Array(groupId, 'utf8');
  if (groupIdBytes.byteLength < MIN_GROUP_ID_BYTE_LENGTH) {
    throw new Error(`Group Id too short. Must be at least ${MIN_GROUP_ID_BYTE_LENGTH} bytes.`);
  }

  const sessionId = computeSessionId(groupIdBytes);
  const initialEpoch = createInitialEpoch(sessionId);

  const initialEpochMessage = initialEpoch.serialize();
  initialEpoch.delete();
  return createVirgilGroupSession([initialEpochMessage]);
}

export function importGroupSession(epochMessages: Data[]) {
  ensureModulesLoaded();
  if (!Array.isArray(epochMessages)) {
    throw new Error('Epoch messages must be an array.');
  }

  if (epochMessages.length === 0) {
    throw new Error('Epoch messages must not be empty.');
  }

  return createVirgilGroupSession(epochMessages.map(it => dataToUint8Array(it, 'base64')));
}

function ensureModulesLoaded() {
  if (!foundationModules) {
    foundationModules = getFoundationModules();
    random = new foundationModules.CtrDrbg();
    random.setupDefaults();
  }
}

function computeSessionId(groupId: Uint8Array) {
  const sha512 = new foundationModules.Sha512();
  try {
    return sha512.hash(groupId).subarray(0, 32);
  } finally {
    sha512.delete();
  }
}

function createInitialEpoch(sessionId: Uint8Array) {
  const ticket = new foundationModules.GroupSessionTicket();
  ticket.rng = random;
  try {
    ticket.setupTicketAsNew(sessionId);
    return ticket.getTicketMessage();
  } finally {
    ticket.delete();
  }
}
