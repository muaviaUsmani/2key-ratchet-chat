import * as fs from 'fs';

import {
  AsymmetricRatchet,
  ECPublicKey,
  IJsonIdentity,
  Identity,
  PreKeyBundleProtocol,
  PreKeyMessageProtocol,
  setEngine
} from "2key-ratchet";

import { Crypto } from "@peculiar/webcrypto";

setEngine("WebCrypto NodeJS", new Crypto());

const generateKeys = async () => {
  let identityKey: Identity;
  try {
    identityKey = await Identity.create(16453, 1, 1);
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
      preKeyBuffer: Buffer.from(uint16String).toString('base64')
    };
  } catch (error) {
    throw error;
  }
}

const generateKeysForUsers = async () => {
  try {
    let AliceKeySet = await generateKeys();
    console.log('Alice\'s Key Set: ', AliceKeySet);
    // let BobKeySet = await generateKeys();
    // console.log('Bob\'s Key Set:', BobKeySet); 
  } catch (error) {
    throw error; 
  }
}

const encryptMessage = async (receiversPreKeyBase64: string, message: string) => {
  try {
    const preKeyBundle = await getPreKeyBundle(receiversPreKeyBase64);
    const senderKey: Identity = await getIdentityKey();
    const cipherObject = await AsymmetricRatchet.create(senderKey, preKeyBundle);
    let messageBuffer = Buffer.from(message, 'utf-8');
    const preKeyMessage = await cipherObject.encrypt(messageBuffer);
    const encryptedMessageBuffer = await preKeyMessage.exportProto();
    let encryptedMessage = new Uint16Array(encryptedMessageBuffer).toString();
    encryptedMessage = Buffer.from(encryptedMessage).toString('base64');
    console.log(encryptedMessage);
  } catch (error) {
    throw error;
  }
}

const decryptMessage = async (messageProtocolBase64: string) => {
  try {
    const messageProtocol = await getPreKeyMessageBundle(messageProtocolBase64);
    const receiverKey = JSON.parse(fs.readFileSync('alice.json', 'utf8')) as IJsonIdentity;
    let receiverKeyIdentity = await Identity.fromJSON(receiverKey);
    const cipherObject = await AsymmetricRatchet.create(receiverKeyIdentity, messageProtocol);
    const signedMessage = await cipherObject.decrypt(messageProtocol.signedMessage);
    const message = Buffer.from(signedMessage).toString("utf-8");
    console.log(message); 
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

const main = (args) => {
  args = args.slice(2);

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
    default:
      break;
  }
};

main(process.argv);