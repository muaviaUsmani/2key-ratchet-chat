"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
var fs = require("fs");
var _2key_ratchet_1 = require("2key-ratchet");
var webcrypto_1 = require("@peculiar/webcrypto");
_2key_ratchet_1.setEngine("WebCrypto NodeJS", new webcrypto_1.Crypto());
var generateKeys = function () { return __awaiter(void 0, void 0, void 0, function () {
    var identityKey, preKeyBundle, preKey, keyArrayBuffer, uint16String, _a, _b, _c, _d, _e, error_1;
    var _f;
    return __generator(this, function (_g) {
        switch (_g.label) {
            case 0:
                _g.trys.push([0, 7, , 8]);
                return [4 /*yield*/, _2key_ratchet_1.Identity.create(16453, 1, 1)];
            case 1:
                identityKey = _g.sent();
                preKeyBundle = new _2key_ratchet_1.PreKeyBundleProtocol();
                return [4 /*yield*/, preKeyBundle.identity.fill(identityKey)];
            case 2:
                _g.sent();
                preKeyBundle.registrationId = identityKey.id;
                preKey = identityKey.signedPreKeys[0];
                preKeyBundle.preKeySigned.id = 0;
                preKeyBundle.preKeySigned.key = preKey.publicKey;
                return [4 /*yield*/, preKeyBundle.preKeySigned.sign(identityKey.signingKey.privateKey)];
            case 3:
                _g.sent();
                return [4 /*yield*/, preKeyBundle.exportProto()];
            case 4:
                keyArrayBuffer = _g.sent();
                uint16String = new Uint16Array(keyArrayBuffer).toString();
                _b = (_a = fs).writeFileSync;
                _c = ['alice.json'];
                _e = (_d = JSON).stringify;
                return [4 /*yield*/, identityKey.toJSON()];
            case 5:
                _b.apply(_a, _c.concat([_e.apply(_d, [_g.sent()])]));
                _f = {};
                return [4 /*yield*/, identityKey.toJSON()];
            case 6: return [2 /*return*/, (_f.identityKey = _g.sent(),
                    _f.preKeyBuffer = Buffer.from(uint16String).toString('base64'),
                    _f)];
            case 7:
                error_1 = _g.sent();
                throw error_1;
            case 8: return [2 /*return*/];
        }
    });
}); };
var generateKeysForUsers = function () { return __awaiter(void 0, void 0, void 0, function () {
    var AliceKeySet, error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                return [4 /*yield*/, generateKeys()];
            case 1:
                AliceKeySet = _a.sent();
                console.log('Alice\'s Key Set: ', AliceKeySet);
                return [3 /*break*/, 3];
            case 2:
                error_2 = _a.sent();
                throw error_2;
            case 3: return [2 /*return*/];
        }
    });
}); };
var encryptMessage = function (receiversPreKeyBase64, message) { return __awaiter(void 0, void 0, void 0, function () {
    var preKeyBundle, senderKey, cipherObject, messageBuffer, preKeyMessage, encryptedMessageBuffer, encryptedMessage, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 6, , 7]);
                return [4 /*yield*/, getPreKeyBundle(receiversPreKeyBase64)];
            case 1:
                preKeyBundle = _a.sent();
                return [4 /*yield*/, getIdentityKey()];
            case 2:
                senderKey = _a.sent();
                return [4 /*yield*/, _2key_ratchet_1.AsymmetricRatchet.create(senderKey, preKeyBundle)];
            case 3:
                cipherObject = _a.sent();
                messageBuffer = Buffer.from(message, 'utf-8');
                return [4 /*yield*/, cipherObject.encrypt(messageBuffer)];
            case 4:
                preKeyMessage = _a.sent();
                return [4 /*yield*/, preKeyMessage.exportProto()];
            case 5:
                encryptedMessageBuffer = _a.sent();
                encryptedMessage = new Uint16Array(encryptedMessageBuffer).toString();
                encryptedMessage = Buffer.from(encryptedMessage).toString('base64');
                console.log(encryptedMessage);
                return [3 /*break*/, 7];
            case 6:
                error_3 = _a.sent();
                throw error_3;
            case 7: return [2 /*return*/];
        }
    });
}); };
var decryptMessage = function (messageProtocolBase64) { return __awaiter(void 0, void 0, void 0, function () {
    var messageProtocol, receiverKey, receiverKeyIdentity, cipherObject, signedMessage, message, error_4;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 5, , 6]);
                return [4 /*yield*/, getPreKeyMessageBundle(messageProtocolBase64)];
            case 1:
                messageProtocol = _a.sent();
                receiverKey = JSON.parse(fs.readFileSync('alice.json', 'utf8'));
                return [4 /*yield*/, _2key_ratchet_1.Identity.fromJSON(receiverKey)];
            case 2:
                receiverKeyIdentity = _a.sent();
                console.log(receiverKeyIdentity);
                return [4 /*yield*/, _2key_ratchet_1.AsymmetricRatchet.create(receiverKeyIdentity, messageProtocol)];
            case 3:
                cipherObject = _a.sent();
                console.log(cipherObject);
                return [4 /*yield*/, cipherObject.decrypt(messageProtocol.signedMessage)];
            case 4:
                signedMessage = _a.sent();
                message = Buffer.from(signedMessage).toString("utf-8");
                console.log(message);
                return [3 /*break*/, 6];
            case 5:
                error_4 = _a.sent();
                throw error_4;
            case 6: return [2 /*return*/];
        }
    });
}); };
var getIdentityKey = function () { return __awaiter(void 0, void 0, void 0, function () {
    var identityKey;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, generateKeys()];
            case 1:
                identityKey = (_a.sent()).identityKey;
                return [2 /*return*/, _2key_ratchet_1.Identity.fromJSON(identityKey)];
        }
    });
}); };
var getPreKeyBundle = function (preKeyString) {
    var preKeyDecodedArray = Buffer
        .from(preKeyString, 'base64')
        .toString('binary')
        .split(',')
        .map(function (item) { return parseInt(item); });
    var preKeyBuffer = Uint16Array.of.apply(Uint16Array, preKeyDecodedArray).buffer;
    return _2key_ratchet_1.PreKeyBundleProtocol.importProto(preKeyBuffer);
};
var getPreKeyMessageBundle = function (messageString) {
    var messageDecodedArray = Buffer
        .from(messageString, 'base64')
        .toString('binary')
        .split(',')
        .map(function (item) { return parseInt(item); });
    var messageBuffer = Uint16Array.of.apply(Uint16Array, messageDecodedArray).buffer;
    return _2key_ratchet_1.PreKeyMessageProtocol.importProto(messageBuffer);
};
var main = function (args) {
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
