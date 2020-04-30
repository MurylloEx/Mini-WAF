const cryptojs = require('crypto-js');

const SHA3OutputLength = {
    SHA3_LENGTH_224: 224,
    SHA3_LENGTH_256: 256,
    SHA3_LENGTH_384: 384,
    SHA3_LENGTH_512: 512
}

/**Codifica uma string UTF16 em uma string Base64.
 * 
 * @param {string} sString String em UTF16.
 * @see https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding#The_.22Unicode_Problem.22
 */
function Base64EncodeUTF16(sString) {
    let aUTF16CodeUnits = new Uint16Array(sString.length);
    Array.prototype.forEach.call(aUTF16CodeUnits, function (el, idx, arr) { arr[idx] = sString.charCodeAt(idx); });
    return btoa(String.fromCharCode.apply(null, new Uint8Array(aUTF16CodeUnits.buffer)));
}

/**Decodifica uma string Base64 em uma string UTF16.
 * 
 * @param {string} sBase64 String em Base64.
 * @see https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding#The_.22Unicode_Problem.22
 */
function Base64DecodeUTF16(sBase64) {
    let sBinaryString = atob(sBase64), aBinaryView = new Uint8Array(sBinaryString.length);
    Array.prototype.forEach.call(aBinaryView, function (el, idx, arr) { arr[idx] = sBinaryString.charCodeAt(idx); });
    return String.fromCharCode.apply(null, new Uint16Array(aBinaryView.buffer));
}

function MD5Hash(str){
    return cryptojs.MD5(str);
}

function SHA1Hash(str){
    return cryptojs.SHA1(str);
}

function SHA256Hash(str){
    return cryptojs.SHA256(str);
}

function SHA512Hash(str){
    return cryptojs.SHA512(str);
}

function SHA3Hash(str, sha3Length){
    return cryptojs.SHA3(str, {outputLength : sha3Length});
}

function RC4Encrypt(toEncrypt, secretKey){
    return cryptojs.RC4.encrypt(toEncrypt, secretKey);
}

function RC4Decrypt(toDecrypt, secretKey){
    return cryptojs.RC4.decrypt(toDecrypt, secretKey);
}

module.exports = {
    SHA3OutputLength: SHA3OutputLength,
    Base64EncodeUTF16: Base64EncodeUTF16,
    Base64DecodeUTF16: Base64DecodeUTF16,
    MD5Hash: MD5Hash,
    SHA1Hash: SHA1Hash,
    SHA256Hash: SHA256Hash,
    SHA512Hash: SHA512Hash,
    SHA3Hash: SHA3Hash,
    RC4Encrypt: RC4Encrypt,
    RC4Decrypt: RC4Decrypt
}