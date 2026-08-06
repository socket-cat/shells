/**
 * @author Carles Ortega Ragull <ragull@socket.cat> (https://socket.cat)
 * @copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Wire protocol v3 — native WebCrypto:
 *   Key agreement : ECDH on P-256 (raw SEC1 point, base64)
 *   Key derivation: HKDF-SHA256 (salt = PBKDF2(secret), info = "shells-v3-{s2c|c2s|api}" || SHA-256(sPub||cPub))
 *   Auth proofs   : HMAC-SHA256 keyed by the PBKDF2 secret hash
 *   Stream AEAD   : AES-256-GCM, 12-byte random nonce per message, inline in every frame
 *                   Binary frame = [type:1][nonce:12][ciphertext||tag]
 */

window.ShellsCrypto = (function () {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const AES_GCM = { name: 'AES-GCM' };
  const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' };
  const HKDF_SHA256 = { name: 'HKDF' };
  const HMAC_SHA256 = { name: 'HMAC', hash: 'SHA-256' };

  function toB64(buf) {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }

  function fromB64(str) {
    const bin = atob(str);
    const a = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }

  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  }

  async function importAesKey(rawBytes) {
    return crypto.subtle.importKey('raw', rawBytes, AES_GCM, false, ['encrypt', 'decrypt']);
  }

  // HKDF-SHA256: derive `len` bytes from ikm with the given salt and info.
  async function hkdf(ikm, saltBytes, infoBytes, len) {
    const baseKey = await crypto.subtle.importKey('raw', ikm, HKDF_SHA256, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: infoBytes },
      baseKey,
      len * 8
    );
    return new Uint8Array(bits);
  }

  function sidToBuffer(sid) {
    if (!sid) return new Uint8Array(16);
    const hex = sid.replace(/-/g, '');
    const buf = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      buf[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return buf;
  }

  function bufferToSid(buf) {
    if (buf.length < 16) return '';
    let hex = '';
    for (let i = 0; i < 16; i++) hex += buf[i].toString(16).padStart(2, '0');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  }

  async function createCryptoState() {
    const keyPair = await crypto.subtle.generateKey(ECDH_P256, true, ['deriveBits']);
    const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    return {
      keyPair,
      publicKeyB64: toB64(rawPub),
      rawPublicKey: rawPub,
      encKey: null,   // client -> server (c2s)
      decKey: null,   // server -> client (s2c)
      apiKey: null,
      cryptoReady: false
    };
  }

  async function getHmacKey(state) {
    if (state._hmacKey) return state._hmacKey;
    state._hmacKey = await crypto.subtle.importKey(
      'raw', state.secretHash, HMAC_SHA256, false, ['sign', 'verify']
    );
    return state._hmacKey;
  }

  async function generateHMACProof(state, msgBytes) {
    if (!state.secretHash) throw new Error('Secret hash not available');
    const key = await getHmacKey(state);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msgBytes));
    return toB64(sig);
  }

  async function verifyHMACProof(state, msgBytes, proofB64) {
    if (!state.secretHash) throw new Error('Secret hash not available');
    const key = await getHmacKey(state);
    return crypto.subtle.verify('HMAC', key, fromB64(proofB64), msgBytes);
  }

  async function handleCryptoAck(state, serverPublicKeyB64, appSecretHash, serverAuthProof) {
    state.secretHash = appSecretHash instanceof Uint8Array ? appSecretHash : new Uint8Array(appSecretHash);

    const serverPub = fromB64(serverPublicKeyB64);
    if (serverPub.length !== 65 || serverPub[0] !== 0x04) {
      throw new Error('Invalid server public key');
    }

    if (serverAuthProof) {
      const ok = await verifyHMACProof(state, serverPub, serverAuthProof);
      if (!ok) throw new Error('Server authentication failed');
    }

    const serverPubKey = await crypto.subtle.importKey('raw', serverPub, ECDH_P256, false, []);

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: serverPubKey }, state.keyPair.privateKey, 256
    );
    const shared = new Uint8Array(sharedBits);
    if (shared.length !== 32) throw new Error('Invalid ECDH shared secret');

    const ctx = await sha256(concat(serverPub, state.rawPublicKey));
    const salt = state.secretHash;

    const sendKey = await hkdf(shared, salt, concat(encoder.encode('shells-v3-c2s'), ctx), 32);
    const recvKey = await hkdf(shared, salt, concat(encoder.encode('shells-v3-s2c'), ctx), 32);
    const apiKeyBytes = await hkdf(shared, salt, concat(encoder.encode('shells-v3-api'), ctx), 32);

    state.encKey = await importAesKey(sendKey);
    state.decKey = await importAesKey(recvKey);
    state.apiKey = await importAesKey(apiKeyBytes);
    state.cryptoReady = true;
  }

  // Encrypt for the WS stream. Returns nonce(12) || ciphertext||tag.
  async function encrypt(state, data) {
    if (!state.cryptoReady) throw new Error('Crypto session not ready');
    const msg = (typeof data === 'string') ? encoder.encode(data) : data;
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, state.encKey, msg));
    const out = new Uint8Array(12 + ct.length);
    out.set(nonce, 0);
    out.set(ct, 12);
    return out;
  }

  // Decrypt a WS stream frame body: nonce(12) || ciphertext||tag.
  async function decrypt(state, data) {
    if (!state.cryptoReady) throw new Error('Crypto session not ready');
    const buf = (typeof data === 'string') ? fromB64(data) : data;
    if (buf.length < 12 + 16) throw new Error('Invalid encrypted payload');
    const nonce = buf.subarray(0, 12);
    const ct = buf.subarray(12);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, state.decKey, ct);
    return new Uint8Array(pt);
  }

  async function encryptPayload(apiKey, plaintext) {
    if (!apiKey) throw new Error('apiKey not available');
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const msg = (typeof plaintext === 'string') ? encoder.encode(plaintext) : plaintext;
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, apiKey, msg));
    return { nonce: toB64(nonce), ciphertext: toB64(ct) };
  }

  async function decryptPayload(apiKey, nonceB64, ciphertextB64) {
    if (!apiKey) throw new Error('apiKey not available');
    const nonce = fromB64(nonceB64);
    const ct = fromB64(ciphertextB64);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, apiKey, ct);
    return decoder.decode(pt);
  }

  return {
    createCryptoState,
    handleCryptoAck,
    encrypt,
    decrypt,
    encryptPayload,
    decryptPayload,
    generateHMACProof,
    sidToBuffer,
    bufferToSid
  };
})();
