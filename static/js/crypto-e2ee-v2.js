/**
 * End-to-End Encryption (E2EE) Library for drop.i2p
 *
 * Uses XChaCha20-Poly1305 for authenticated encryption.
 * This is a pure JavaScript implementation for browser compatibility.
 *
 * Based on noble-ciphers concepts but simplified for our use case.
 */

const E2EE = (function() {
    'use strict';

    const CHUNK_SIZE = 256 * 1024; // 256KB - matches server chunk size
    const KEY_SIZE = 32; // 256-bit key
    const NONCE_SIZE = 24; // XChaCha20 uses 24-byte nonces
    const TAG_SIZE = 16; // Poly1305 tag size

    // ========== Utility Functions ==========

    function randomBytes(length) {
        const bytes = new Uint8Array(length);
        crypto.getRandomValues(bytes);
        return bytes;
    }

    function bytesToBase64(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToBytes(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    function concatBytes(...arrays) {
        const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const arr of arrays) {
            result.set(arr, offset);
            offset += arr.length;
        }
        return result;
    }

    function numberToBytes(num, length) {
        const bytes = new Uint8Array(length);
        for (let i = length - 1; i >= 0; i--) {
            bytes[i] = num & 0xff;
            num = Math.floor(num / 256);
        }
        return bytes;
    }

    function bytesToNumber(bytes) {
        let num = 0;
        for (let i = 0; i < bytes.length; i++) {
            num = num * 256 + bytes[i];
        }
        return num;
    }

    // ========== ChaCha20 Core ==========

    function rotl(a, b) {
        return ((a << b) | (a >>> (32 - b))) >>> 0;
    }

    function quarterRound(state, a, b, c, d) {
        state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl(state[d] ^ state[a], 16);
        state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl(state[b] ^ state[c], 12);
        state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl(state[d] ^ state[a], 8);
        state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl(state[b] ^ state[c], 7);
    }

    function chacha20Block(key, counter, nonce) {
        // Initialize state
        const state = new Uint32Array(16);

        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key (8 words)
        const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
        for (let i = 0; i < 8; i++) {
            state[4 + i] = keyView.getUint32(i * 4, true);
        }

        // Counter
        state[12] = counter >>> 0;

        // Nonce (3 words for standard ChaCha20)
        const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
        state[13] = nonceView.getUint32(0, true);
        state[14] = nonceView.getUint32(4, true);
        state[15] = nonceView.getUint32(8, true);

        // Copy initial state
        const working = new Uint32Array(state);

        // 20 rounds (10 double rounds)
        for (let i = 0; i < 10; i++) {
            // Column rounds
            quarterRound(working, 0, 4, 8, 12);
            quarterRound(working, 1, 5, 9, 13);
            quarterRound(working, 2, 6, 10, 14);
            quarterRound(working, 3, 7, 11, 15);
            // Diagonal rounds
            quarterRound(working, 0, 5, 10, 15);
            quarterRound(working, 1, 6, 11, 12);
            quarterRound(working, 2, 7, 8, 13);
            quarterRound(working, 3, 4, 9, 14);
        }

        // Add initial state
        for (let i = 0; i < 16; i++) {
            working[i] = (working[i] + state[i]) >>> 0;
        }

        // Convert to bytes
        const output = new Uint8Array(64);
        const outView = new DataView(output.buffer);
        for (let i = 0; i < 16; i++) {
            outView.setUint32(i * 4, working[i], true);
        }

        return output;
    }

    // HChaCha20 - used for XChaCha20 key derivation
    function hchacha20(key, nonce16) {
        const state = new Uint32Array(16);

        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
        for (let i = 0; i < 8; i++) {
            state[4 + i] = keyView.getUint32(i * 4, true);
        }

        const nonceView = new DataView(nonce16.buffer, nonce16.byteOffset, nonce16.byteLength);
        state[12] = nonceView.getUint32(0, true);
        state[13] = nonceView.getUint32(4, true);
        state[14] = nonceView.getUint32(8, true);
        state[15] = nonceView.getUint32(12, true);

        for (let i = 0; i < 10; i++) {
            quarterRound(state, 0, 4, 8, 12);
            quarterRound(state, 1, 5, 9, 13);
            quarterRound(state, 2, 6, 10, 14);
            quarterRound(state, 3, 7, 11, 15);
            quarterRound(state, 0, 5, 10, 15);
            quarterRound(state, 1, 6, 11, 12);
            quarterRound(state, 2, 7, 8, 13);
            quarterRound(state, 3, 4, 9, 14);
        }

        const output = new Uint8Array(32);
        const outView = new DataView(output.buffer);
        outView.setUint32(0, state[0], true);
        outView.setUint32(4, state[1], true);
        outView.setUint32(8, state[2], true);
        outView.setUint32(12, state[3], true);
        outView.setUint32(16, state[12], true);
        outView.setUint32(20, state[13], true);
        outView.setUint32(24, state[14], true);
        outView.setUint32(28, state[15], true);

        return output;
    }

    function chacha20Encrypt(key, nonce, plaintext) {
        const output = new Uint8Array(plaintext.length);
        let counter = 0;

        for (let i = 0; i < plaintext.length; i += 64) {
            const block = chacha20Block(key, counter, nonce);
            const remaining = Math.min(64, plaintext.length - i);
            for (let j = 0; j < remaining; j++) {
                output[i + j] = plaintext[i + j] ^ block[j];
            }
            counter++;
        }

        return output;
    }

    // ========== Poly1305 ==========

    function poly1305(key, message) {
        // Simplified Poly1305 implementation
        // Using BigInt for proper 130-bit arithmetic
        const r = clampR(key.slice(0, 16));
        const s = key.slice(16, 32);

        let accumulator = 0n;
        const prime = (1n << 130n) - 5n;

        // Convert r to BigInt
        let rBig = 0n;
        for (let i = 0; i < 16; i++) {
            rBig |= BigInt(r[i]) << BigInt(i * 8);
        }

        // Process message in 16-byte blocks
        for (let i = 0; i < message.length; i += 16) {
            const block = message.slice(i, Math.min(i + 16, message.length));
            let n = 0n;
            for (let j = 0; j < block.length; j++) {
                n |= BigInt(block[j]) << BigInt(j * 8);
            }
            // Add high bit
            n |= 1n << BigInt(block.length * 8);

            accumulator = (accumulator + n) * rBig % prime;
        }

        // Add s
        let sBig = 0n;
        for (let i = 0; i < 16; i++) {
            sBig |= BigInt(s[i]) << BigInt(i * 8);
        }
        accumulator = (accumulator + sBig) % (1n << 128n);

        // Convert to bytes
        const tag = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            tag[i] = Number((accumulator >> BigInt(i * 8)) & 0xffn);
        }

        return tag;
    }

    function clampR(r) {
        const clamped = new Uint8Array(r);
        clamped[3] &= 15;
        clamped[7] &= 15;
        clamped[11] &= 15;
        clamped[15] &= 15;
        clamped[4] &= 252;
        clamped[8] &= 252;
        clamped[12] &= 252;
        return clamped;
    }

    function constantTimeEqual(a, b) {
        if (a.length !== b.length) return false;
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result === 0;
    }

    // ========== XChaCha20-Poly1305 ==========

    function xchacha20poly1305Encrypt(key, nonce24, plaintext) {
        // Derive subkey using HChaCha20
        const subkey = hchacha20(key, nonce24.slice(0, 16));

        // Build nonce for ChaCha20: 4 zero bytes + last 8 bytes of original nonce
        const chacha20Nonce = new Uint8Array(12);
        chacha20Nonce.set(nonce24.slice(16, 24), 4);

        // Generate Poly1305 key (first block with counter 0)
        const polyKey = chacha20Block(subkey, 0, chacha20Nonce).slice(0, 32);

        // Encrypt with counter starting at 1
        const ciphertext = new Uint8Array(plaintext.length);
        let counter = 1;
        for (let i = 0; i < plaintext.length; i += 64) {
            const block = chacha20Block(subkey, counter, chacha20Nonce);
            const remaining = Math.min(64, plaintext.length - i);
            for (let j = 0; j < remaining; j++) {
                ciphertext[i + j] = plaintext[i + j] ^ block[j];
            }
            counter++;
        }

        // Compute tag
        const tag = poly1305(polyKey, ciphertext);

        return concatBytes(ciphertext, tag);
    }

    function xchacha20poly1305Decrypt(key, nonce24, ciphertextWithTag) {
        if (ciphertextWithTag.length < TAG_SIZE) {
            throw new Error('Ciphertext too short');
        }

        const ciphertext = ciphertextWithTag.slice(0, -TAG_SIZE);
        const tag = ciphertextWithTag.slice(-TAG_SIZE);

        // Derive subkey using HChaCha20
        const subkey = hchacha20(key, nonce24.slice(0, 16));

        // Build nonce for ChaCha20
        const chacha20Nonce = new Uint8Array(12);
        chacha20Nonce.set(nonce24.slice(16, 24), 4);

        // Generate Poly1305 key
        const polyKey = chacha20Block(subkey, 0, chacha20Nonce).slice(0, 32);

        // Verify tag
        const expectedTag = poly1305(polyKey, ciphertext);
        if (!constantTimeEqual(tag, expectedTag)) {
            throw new Error('Authentication failed');
        }

        // Decrypt
        const plaintext = new Uint8Array(ciphertext.length);
        let counter = 1;
        for (let i = 0; i < ciphertext.length; i += 64) {
            const block = chacha20Block(subkey, counter, chacha20Nonce);
            const remaining = Math.min(64, ciphertext.length - i);
            for (let j = 0; j < remaining; j++) {
                plaintext[i + j] = ciphertext[i + j] ^ block[j];
            }
            counter++;
        }

        return plaintext;
    }

    // ========== SHA-256 (Pure JavaScript) ==========

    // SHA-256 constants
    const SHA256_K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);

    function sha256(message) {
        // Ensure message is Uint8Array
        if (!(message instanceof Uint8Array)) {
            message = new TextEncoder().encode(message);
        }

        // Initial hash values
        let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

        // Pre-processing: adding padding bits
        const msgLen = message.length;
        const bitLen = msgLen * 8;

        // Message needs to be padded to 512-bit blocks (64 bytes)
        // Padding: 1 bit, then zeros, then 64-bit length
        const padLen = (msgLen % 64 < 56) ? (56 - msgLen % 64) : (120 - msgLen % 64);
        const padded = new Uint8Array(msgLen + padLen + 8);
        padded.set(message);
        padded[msgLen] = 0x80;

        // Append length in bits as big-endian 64-bit
        const view = new DataView(padded.buffer);
        // JavaScript can only handle 53-bit integers safely, but for our use case this is fine
        view.setUint32(padded.length - 4, bitLen >>> 0, false);

        const w = new Uint32Array(64);

        // Process each 64-byte block
        for (let offset = 0; offset < padded.length; offset += 64) {
            // Copy block into first 16 words of w
            for (let i = 0; i < 16; i++) {
                w[i] = (padded[offset + i * 4] << 24) |
                       (padded[offset + i * 4 + 1] << 16) |
                       (padded[offset + i * 4 + 2] << 8) |
                       (padded[offset + i * 4 + 3]);
            }

            // Extend the first 16 words into the remaining 48 words
            for (let i = 16; i < 64; i++) {
                const s0 = (rotateRight(w[i-15], 7) ^ rotateRight(w[i-15], 18) ^ (w[i-15] >>> 3)) >>> 0;
                const s1 = (rotateRight(w[i-2], 17) ^ rotateRight(w[i-2], 19) ^ (w[i-2] >>> 10)) >>> 0;
                w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
            }

            // Initialize working variables
            let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

            // Main loop
            for (let i = 0; i < 64; i++) {
                const S1 = (rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)) >>> 0;
                const ch = ((e & f) ^ (~e & g)) >>> 0;
                const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
                const S0 = (rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)) >>> 0;
                const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
                const temp2 = (S0 + maj) >>> 0;

                h = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }

            // Add compressed chunk to current hash value
            h0 = (h0 + a) >>> 0;
            h1 = (h1 + b) >>> 0;
            h2 = (h2 + c) >>> 0;
            h3 = (h3 + d) >>> 0;
            h4 = (h4 + e) >>> 0;
            h5 = (h5 + f) >>> 0;
            h6 = (h6 + g) >>> 0;
            h7 = (h7 + h) >>> 0;
        }

        // Produce final hash value (big-endian)
        const hash = new Uint8Array(32);
        const hashView = new DataView(hash.buffer);
        hashView.setUint32(0, h0, false);
        hashView.setUint32(4, h1, false);
        hashView.setUint32(8, h2, false);
        hashView.setUint32(12, h3, false);
        hashView.setUint32(16, h4, false);
        hashView.setUint32(20, h5, false);
        hashView.setUint32(24, h6, false);
        hashView.setUint32(28, h7, false);

        return hash;
    }

    function rotateRight(x, n) {
        return ((x >>> n) | (x << (32 - n))) >>> 0;
    }

    // ========== HMAC-SHA256 ==========

    function hmacSha256(key, message) {
        const blockSize = 64;

        // If key is longer than block size, hash it
        if (key.length > blockSize) {
            key = sha256(key);
        }

        // Pad key to block size
        const paddedKey = new Uint8Array(blockSize);
        paddedKey.set(key);

        // Create inner and outer padded keys
        const ipad = new Uint8Array(blockSize);
        const opad = new Uint8Array(blockSize);
        for (let i = 0; i < blockSize; i++) {
            ipad[i] = paddedKey[i] ^ 0x36;
            opad[i] = paddedKey[i] ^ 0x5c;
        }

        // Inner hash: H(ipad || message)
        const innerData = concatBytes(ipad, message);
        const innerHash = sha256(innerData);

        // Outer hash: H(opad || innerHash)
        const outerData = concatBytes(opad, innerHash);
        return sha256(outerData);
    }

    // ========== HKDF Key Derivation (Pure JavaScript) ==========

    function hkdfExtract(salt, ikm) {
        // If no salt, use zero-filled salt of hash length
        if (!salt || salt.length === 0) {
            salt = new Uint8Array(32);
        }
        return hmacSha256(salt, ikm);
    }

    function hkdfExpand(prk, info, length) {
        const hashLen = 32; // SHA-256 output length
        const n = Math.ceil(length / hashLen);

        if (n > 255) {
            throw new Error('HKDF: requested length too long');
        }

        const okm = new Uint8Array(n * hashLen);
        let prev = new Uint8Array(0);

        for (let i = 0; i < n; i++) {
            const data = concatBytes(prev, info, new Uint8Array([i + 1]));
            prev = hmacSha256(prk, data);
            okm.set(prev, i * hashLen);
        }

        return okm.slice(0, length);
    }

    function hkdfDerive(key, salt, info, length) {
        const prk = hkdfExtract(salt, key);
        return hkdfExpand(prk, info, length);
    }

    function deriveChunkKeyAndNonce(masterKey, chunkIndex) {
        const info = numberToBytes(chunkIndex, 8);
        const salt = new TextEncoder().encode('chunk');
        const derived = hkdfDerive(masterKey, salt, info, KEY_SIZE + NONCE_SIZE);
        return {
            key: derived.slice(0, KEY_SIZE),
            nonce: derived.slice(KEY_SIZE)
        };
    }

    // ========== High-Level API ==========

    function generateKey() {
        return randomBytes(KEY_SIZE);
    }

    function keyToString(key) {
        return bytesToBase64(key);
    }

    function stringToKey(str) {
        const bytes = base64ToBytes(str);
        if (bytes.length !== KEY_SIZE) {
            throw new Error(`Invalid key length: expected ${KEY_SIZE} bytes, got ${bytes.length}`);
        }
        return bytes;
    }

    async function encryptFile(file, key, onProgress) {
        const filename = file.name;
        const mimeType = file.type || 'application/octet-stream';
        const originalSize = file.size;

        // Encrypt filename
        const filenameBytes = new TextEncoder().encode(filename);
        const filenameNonce = randomBytes(NONCE_SIZE);
        const encryptedFilename = xchacha20poly1305Encrypt(key, filenameNonce, filenameBytes);

        // Build header
        const header = {
            version: 1,
            algorithm: 'XChaCha20-Poly1305',
            encryptedFilename: bytesToBase64(encryptedFilename),
            filenameNonce: bytesToBase64(filenameNonce),
            originalSize: originalSize,
            mimeType: mimeType,
            chunkSize: CHUNK_SIZE
        };
        const headerJson = JSON.stringify(header);
        const headerBytes = new TextEncoder().encode(headerJson);

        // Calculate total chunks for progress
        const totalChunks = Math.ceil(originalSize / CHUNK_SIZE);
        let processedChunks = 0;

        // Encrypt chunks
        const chunks = [];
        let offset = 0;
        let chunkIndex = 0;

        while (offset < originalSize) {
            const end = Math.min(offset + CHUNK_SIZE, originalSize);
            const slice = file.slice(offset, end);
            const plaintext = new Uint8Array(await slice.arrayBuffer());

            // Derive per-chunk key and nonce
            const { key: chunkKey, nonce: chunkNonce } = deriveChunkKeyAndNonce(key, chunkIndex);

            // Encrypt chunk
            const ciphertext = xchacha20poly1305Encrypt(chunkKey, chunkNonce, plaintext);

            // Store chunk with length prefix
            const chunkLengthBytes = numberToBytes(ciphertext.length, 4);
            chunks.push(concatBytes(chunkLengthBytes, ciphertext));

            offset = end;
            chunkIndex++;
            processedChunks++;

            if (onProgress) {
                onProgress(processedChunks / totalChunks * 100);
            }
        }

        // Assemble final blob: [header_length][header][chunk0][chunk1]...
        const headerLengthBytes = numberToBytes(headerBytes.length, 4);
        const allChunks = concatBytes(headerLengthBytes, headerBytes, ...chunks);

        return new Blob([allChunks], { type: 'application/octet-stream' });
    }

    async function decryptFile(encryptedData, key, onProgress) {
        // Handle both Blob/ArrayBuffer and Uint8Array inputs
        let data;
        if (encryptedData instanceof Uint8Array) {
            data = encryptedData;
        } else if (encryptedData instanceof Blob) {
            data = new Uint8Array(await encryptedData.arrayBuffer());
        } else if (encryptedData instanceof ArrayBuffer) {
            data = new Uint8Array(encryptedData);
        } else {
            throw new Error('Invalid input type for decryption');
        }

        // Parse header length
        const headerLength = bytesToNumber(data.slice(0, 4));
        const headerBytes = data.slice(4, 4 + headerLength);
        const header = JSON.parse(new TextDecoder().decode(headerBytes));

        // Verify version
        if (header.version !== 1) {
            throw new Error('Unsupported encryption version');
        }

        // Decrypt filename
        const encryptedFilename = base64ToBytes(header.encryptedFilename);
        const filenameNonce = base64ToBytes(header.filenameNonce);
        const filenameBytes = xchacha20poly1305Decrypt(key, filenameNonce, encryptedFilename);
        const filename = new TextDecoder().decode(filenameBytes);

        // Calculate total chunks for progress
        let dataOffset = 4 + headerLength;
        let chunksData = [];
        let chunkIndex = 0;
        let totalEstimatedChunks = Math.ceil(header.originalSize / header.chunkSize);

        // Decrypt chunks
        while (dataOffset < data.length) {
            const chunkLength = bytesToNumber(data.slice(dataOffset, dataOffset + 4));
            dataOffset += 4;

            const ciphertext = data.slice(dataOffset, dataOffset + chunkLength);
            dataOffset += chunkLength;

            // Derive per-chunk key and nonce
            const { key: chunkKey, nonce: chunkNonce } = deriveChunkKeyAndNonce(key, chunkIndex);

            // Decrypt chunk
            const plaintext = xchacha20poly1305Decrypt(chunkKey, chunkNonce, ciphertext);
            chunksData.push(plaintext);

            chunkIndex++;

            if (onProgress) {
                onProgress(Math.min(chunkIndex / totalEstimatedChunks * 100, 100));
            }
        }

        // Assemble decrypted file
        const decryptedData = concatBytes(...chunksData);

        return { data: decryptedData, filename, mimeType: header.mimeType };
    }

    // ========== Export Public API ==========

    return {
        generateKey,
        keyToString,
        stringToKey,
        encryptFile,
        decryptFile,
        CHUNK_SIZE,
        KEY_SIZE
    };
})();

// Make available globally
if (typeof window !== 'undefined') {
    window.E2EE = E2EE;
}
