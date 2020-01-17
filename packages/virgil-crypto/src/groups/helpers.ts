import { toBuffer } from '@virgilsecurity/data-utils';

import { getFoundationModules } from '../foundationModules';
import { getRandom } from '../getRandom';
import { FoundationModules, IGroupSessionMessageInfo } from '../types';

export function parseGroupSessionMessage(messageData: Uint8Array): IGroupSessionMessageInfo {
  const message = getFoundationModules().GroupSessionMessage.deserialize(messageData);
  const info: IGroupSessionMessageInfo = {
    epochNumber: message.getEpoch(),
    sessionId: toBuffer(message.getSessionId()).toString('hex'),
    data: toBuffer(messageData).toString('base64'),
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
  const module = getFoundationModules();
  const session = new module.GroupSession();
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
  const foundation = getFoundationModules();
  const sha512 = new foundation.Sha512();
  try {
    return sha512.hash(groupId).subarray(0, 32);
  } finally {
    sha512.delete();
  }
}

export function createInitialEpoch(sessionId: Uint8Array) {
  const foundation = getFoundationModules();
  const ticket = new foundation.GroupSessionTicket();
  ticket.rng = getRandom();
  try {
    ticket.setupTicketAsNew(sessionId);
    return ticket.getTicketMessage();
  } finally {
    ticket.delete();
  }
}
