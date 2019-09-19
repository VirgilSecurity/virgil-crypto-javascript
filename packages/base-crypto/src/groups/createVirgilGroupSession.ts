import { toBuffer, dataToUint8Array } from '@virgilsecurity/data-utils';
import { Data, IGroupSession } from '../types';
import { validatePrivateKey, validatePublicKey } from '../validators';
import { getLowLevelPrivateKey } from '../privateKeyUtils';
import { importPublicKey } from '../keyProvider';
import { VirgilPrivateKey } from '../VirgilPrivateKey';
import { VirgilPublicKey } from '../VirgilPublicKey';
import { getFoundationModules } from '../foundationModules';
import {
  createLowLevelSession,
  getEpochNumberFromEpochMessage,
  parseGroupSessionMessage,
} from './helpers';

export function createVirgilGroupSession(epochMessages: Uint8Array[]): IGroupSession {
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
      const lowLevelPrivateKey = getLowLevelPrivateKey(signingPrivateKey);
      let session: FoundationModules.GroupSession | undefined;

      try {
        session = createLowLevelSession(epochMessages);
        const message = session.encrypt(dataBytes, lowLevelPrivateKey);
        const encrypted = message.serialize();
        message.delete();
        return toBuffer(encrypted);
      } finally {
        session && session.delete();
        lowLevelPrivateKey.delete();
      }
    },

    decrypt(encryptedData: Data, verifyingPublicKey: VirgilPublicKey) {
      const encryptedDataBytes = dataToUint8Array(encryptedData, 'base64');
      validatePublicKey(verifyingPublicKey);
      const lowLevelPublicKey = importPublicKey(verifyingPublicKey.key);
      let session: FoundationModules.GroupSession | undefined;
      let message: FoundationModules.GroupSessionMessage | undefined;

      try {
        session = createLowLevelSession(epochMessages);
        message = getFoundationModules().GroupSessionMessage.deserialize(encryptedDataBytes);
        return toBuffer(session.decrypt(message, lowLevelPublicKey));
      } finally {
        message && message.delete();
        session && session.delete();
        lowLevelPublicKey.delete();
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

        return parseGroupSessionMessage(newEpochMessage);
      } finally {
        session.delete();
      }
    },

    export() {
      return epochMessages.map(toBuffer);
    },

    parseMessage(messageData: Data) {
      const messageBytes = dataToUint8Array(messageData, 'base64');
      return parseGroupSessionMessage(messageBytes);
    },
  };
}
