import * as fs from 'fs';

import {
  AsymmetricRatchet,
  IJsonIdentity,
  Identity,
  PreKeyBundleProtocol,
  PreKeyMessageProtocol,
  setEngine
} from "2key-ratchet";

import { Convert } from 'pvtsutils';
import { Crypto } from "@peculiar/webcrypto";

const generateKeys = async (id=0, returnBuffer=false) => {
  let identityKey: Identity;
  try {
    identityKey = await Identity.create(id, 1);
    let preKeyBundle = new PreKeyBundleProtocol();
    await preKeyBundle.identity.fill(identityKey);
    preKeyBundle.registrationId = identityKey.id;
    const preKey = identityKey.signedPreKeys[0];
    preKeyBundle.preKeySigned.id = 0;
    preKeyBundle.preKeySigned.key = preKey.publicKey;
    await preKeyBundle.preKeySigned.sign(identityKey.signingKey.privateKey);
    let keyArrayBuffer: ArrayBuffer = await preKeyBundle.exportProto();
    let uint16String = new Uint16Array(keyArrayBuffer).toString();
    fs.writeFileSync('alice.json', JSON.stringify(await identityKey.toJSON()));
    return {
      identityKey: await identityKey.toJSON(),
      preKeyBuffer: returnBuffer ? keyArrayBuffer : Buffer.from(uint16String).toString('base64')
    };
  } catch (error) {
    throw error;
  }
}

const generateKeysForUsers = async () => {
  try {
    let AliceKeySet = await generateKeys(16453);
    console.log('Alice\'s Key Set: ', AliceKeySet);
    // let BobKeySet = await generateKeys();
    // console.log('Bob\'s Key Set:', BobKeySet); 
  } catch (error) {
    throw error; 
  }
}

const encryptMessage = async (receiversPreKey: string | ArrayBuffer, message: string, processBuffers=false) => {
  try {
    let preKeyBundle;
    if (processBuffers) {
      preKeyBundle = await PreKeyBundleProtocol.importProto(receiversPreKey as ArrayBuffer);
    } else {
      preKeyBundle = await getPreKeyBundle(receiversPreKey as string);
    }
    const senderKey: Identity = await getIdentityKey();
    const cipherObject = await AsymmetricRatchet.create(senderKey, preKeyBundle);
    const preKeyMessage = await cipherObject.encrypt(Convert.FromUtf8String(message));
    const encryptedMessageBuffer = await preKeyMessage.exportProto();
    let encryptedMessage = Convert.ToHex(encryptedMessageBuffer);
    console.log("Encrypted message: ", encryptedMessage);
    return processBuffers ? encryptedMessageBuffer : encryptedMessage;
  } catch (error) {
    throw error;
  }
}

const decryptMessage = async (messageProtocolEncrypted: string | ArrayBuffer, identityJson=null, processBuffers=false) => {
  try {
    let messageProtocol;
    if (processBuffers) {
      messageProtocol = await PreKeyMessageProtocol.importProto(messageProtocolEncrypted as ArrayBuffer);
    } else {
      messageProtocol = await getPreKeyMessageBundle(messageProtocolEncrypted as string);
    }
    const receiverKey = identityJson ? identityJson : JSON.parse(fs.readFileSync('alice.json', 'utf8')) as IJsonIdentity;
    let receiverKeyIdentity = await Identity.fromJSON(receiverKey);
    const cipherObject = await AsymmetricRatchet.create(receiverKeyIdentity, messageProtocol);
    const signedMessage = await cipherObject.decrypt(messageProtocol.signedMessage);
    const message = Convert.ToUtf8String(signedMessage);
    console.log("Decrypted message: ", message); 
    return message;
  } catch (error) {
    throw error;
  }
}

const getIdentityKey = async () => {
  const { identityKey } = await generateKeys();
  return Identity.fromJSON(identityKey);
}

const getPreKeyBundle = (preKeyString: string) => {
  const preKeyDecodedArray = Buffer
      .from(preKeyString, 'base64')
      .toString('binary')
      .split(',')
      .map(item => parseInt(item));
  const preKeyBuffer = Uint16Array.of(...preKeyDecodedArray).buffer;
  return PreKeyBundleProtocol.importProto(preKeyBuffer);
}

const getPreKeyMessageBundle = (messageString: string) => {
  const messageDecodedArray = Buffer
      .from(messageString, 'base64')
      .toString('binary')
      .split(',')
      .map(item => parseInt(item));
  const messageBuffer = Uint16Array.of(...messageDecodedArray).buffer;
  return PreKeyMessageProtocol.importProto(messageBuffer);
}

const main = async (args) => {
  args = args.slice(2);

  const crypto = new Crypto();
  setEngine("@peculiar/webcrypto", crypto);

  switch (args[0]) {
    case 'generate':
      generateKeysForUsers();
      break;
    case 'encrypt':
      encryptMessage(args[1], args[2]);
      break;
    case 'decrypt':
      decryptMessage(args[1]);
      break;
    case 'all':
      const {identityKey, preKeyBuffer} = await generateKeys(16453, true);
      console.log("Message to send: ", "Hello there")
      const encryptedMessage = await encryptMessage(preKeyBuffer, "Hello there", true);
      await decryptMessage(encryptedMessage, identityKey, true);
      break;
    default:
      break;
  }
};

main(process.argv);