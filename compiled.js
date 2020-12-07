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
System.register("index", ["@peculiar/webcrypto"], function (exports_1, context_1) {
    "use strict";
    var DKeyRatchet, webcrypto_1, generateKeys, generateKeysForUsers, main;
    var __moduleName = context_1 && context_1.id;
    return {
        setters: [
            function (webcrypto_1_1) {
                webcrypto_1 = webcrypto_1_1;
            }
        ],
        execute: function () {
            DKeyRatchet = require("2key-ratchet");
            DKeyRatchet.setEngine("WebCrypto NodeJS", new webcrypto_1.Crypto());
            generateKeys = function () { return __awaiter(void 0, void 0, void 0, function () {
                var identityKey, preKeyBundle, preKey, keyArrayBuffer, preKeyMessageBundle, isKeyTrusted, error_1;
                return __generator(this, function (_a) {
                    switch (_a.label) {
                        case 0:
                            _a.trys.push([0, 6, , 7]);
                            return [4 /*yield*/, DKeyRatchet.Identity.create(16453, 1, 1)];
                        case 1:
                            identityKey = _a.sent();
                            preKeyBundle = new DKeyRatchet.PreKeyBundleProtocol();
                            return [4 /*yield*/, preKeyBundle.identity.fill(identityKey)];
                        case 2:
                            _a.sent();
                            preKeyBundle.registrationId = identityKey.id;
                            preKey = identityKey.signedPreKeys[0];
                            console.log(preKey.publicKey);
                            preKeyBundle.preKeySigned.id = 1;
                            preKeyBundle.preKeySigned.key = preKey.publicKey;
                            return [4 /*yield*/, preKeyBundle.preKeySigned.sign(identityKey.signingKey.privateKey)];
                        case 3:
                            _a.sent();
                            return [4 /*yield*/, preKeyBundle.exportProto()];
                        case 4:
                            keyArrayBuffer = _a.sent();
                            return [4 /*yield*/, DKeyRatchet.PreKeyBundleProtocol.importProto(keyArrayBuffer)];
                        case 5:
                            preKeyMessageBundle = _a.sent();
                            isKeyTrusted = preKeyMessageBundle.verify(identityKey.signingKey.publicKey);
                            if (!isKeyTrusted) {
                                throw new Error("Error: The PreKey is not trusted");
                            }
                            console.log(identityKey.signingKey.publicKey);
                            return [2 /*return*/, identityKey.signingKey.publicKey];
                        case 6:
                            error_1 = _a.sent();
                            throw error_1;
                        case 7: return [2 /*return*/];
                    }
                });
            }); };
            generateKeysForUsers = function () {
                var AliceKeySet = generateKeys();
                console.log(AliceKeySet);
            };
            main = function (args) {
                args = args.slice(2);
                switch (args[0]) {
                    case 'generate':
                        generateKeysForUsers();
                        break;
                    default:
                        break;
                }
            };
            main(process.argv);
        }
    };
});
