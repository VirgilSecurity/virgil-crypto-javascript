import { toBuffer } from '@virgilsecurity/data-utils';
import { FoundationModules, getFoundationModules } from '../foundationModules';
import { IGroupSessionMessageInfo } from '../types';

const getRandom = (() => {
  let random: FoundationModules.CtrDrbg | undefined;
  return () => {
    if (!random) {
      random = new (getFoundationModules()).CtrDrbg();
      try {
        random.setupDefaults();
      } catch (error) {
        random.delete();
        random = undefined;
        throw error;
      }
    }
    return random;
  };
})();

export function parseGroupSessionMessage(messageData: Uint8Array) {
  const message = getFoundationModules().GroupSessionMessage.deserialize(messageData);
  const info: IGroupSessionMessageInfo = {
    epochNumber: message.getEpoch(),
    sessionId: toBuffer(message.getSessionId()).toString('hex'),
    data: toBuffer(messageData),
  };
  message.delete();
  return info;
}

export function getEpochNumberFromEpochMessage(epochMessageData: Uint8Array) {
  const epoch = getFoundationModules().GroupSessionMessage.deserialize(epochMessageData);
  const epochNumber = epoch.getEpoch();
  epoch.delete();
  return epochNumber;
}

export function createLowLevelSession(epochMessages: Uint8Array[]) {
  const session = new (getFoundationModules()).GroupSession();
  session.rng = getRandom();

  const deleteQueue: FoundationModules.FoundationObject[] = [];
  try {
    for (const epochMessageData of epochMessages) {
      const epoch = getFoundationModules().GroupSessionMessage.deserialize(epochMessageData);
      deleteQueue.push(epoch);
      session.addEpoch(epoch);
    }
    return session;
  } finally {
    while (deleteQueue.length) {
      const obj = deleteQueue.pop();
      obj && obj.delete();
    }
  }
}

export function computeSessionId(groupId: Uint8Array) {
  const sha512 = new (getFoundationModules()).Sha512();
  try {
    return sha512.hash(groupId).subarray(0, 32);
  } finally {
    sha512.delete();
  }
}

export function createInitialEpoch(sessionId: Uint8Array) {
  const ticket = new (getFoundationModules()).GroupSessionTicket();
  ticket.rng = getRandom();
  try {
    ticket.setupTicketAsNew(sessionId);
    return ticket.getTicketMessage();
  } finally {
    ticket.delete();
  }
}
