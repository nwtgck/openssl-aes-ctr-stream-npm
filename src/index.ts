import {ReadableStreamSizedReader} from "readable-stream-sized-reader";
import {mergeUint8Arrays} from "binconv/dist/src/mergeUint8Arrays";

const keyBitSize = 256;
const ivBitSize = 128;
const blockByteSize = 16;

async function deriveKeyAndIvByPbkdf2(salt: Uint8Array, password: string, options: { iterations: number, hash: "SHA-256" }): Promise<{ cryptoKey: CryptoKey, iv: Uint8Array }> {
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );
  const keyIvBits = await window.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: options.iterations,
      hash: options.hash
    },
    keyMaterial,
    keyBitSize + ivBitSize,
  );
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(keyIvBits.slice(0, keyBitSize / 8)),
    { name: "AES-CTR" },
    false,
    ["encrypt", "decrypt"]
  );
  return {
    cryptoKey,
    iv: new Uint8Array(keyIvBits.slice(keyBitSize / 8)),
  }
}

function incrementCounter(counter: Uint8Array) {
  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i]++;
    if(counter[i] !== 0) break;
  }
}

export function aesCtrEncrypt(readableStream: ReadableStream<Uint8Array>, password: string, pbkdf2Options: { iterations: number, hash: "SHA-256" } ): ReadableStream<Uint8Array> {
  const reader = new ReadableStreamSizedReader(readableStream.getReader());
  const salt = crypto.getRandomValues(new Uint8Array(8));
  const keyAndIvPromise = deriveKeyAndIvByPbkdf2(salt, password, pbkdf2Options);
  return new ReadableStream({
    async start(ctrl) {
      ctrl.enqueue(mergeUint8Arrays([
        new TextEncoder().encode('Salted__'),
        salt
      ]));
    },
    async pull(ctrl) {
      const result = await reader.read(blockByteSize);
      if(result.done) {
        ctrl.close();
        return;
      }
      const {cryptoKey, iv: counter} = await keyAndIvPromise;
      const encrypted = await crypto.subtle.encrypt({ name: "AES-CTR", counter: counter, length: ivBitSize }, cryptoKey, result.value);
      ctrl.enqueue(new Uint8Array(encrypted));
      // Increment counter destructively
      incrementCounter(counter);
    }
  });
}

function throwIfUnexpectedLength(result: ReadableStreamDefaultReadResult<Uint8Array>, expectedByteLength: number): asserts result is ReadableStreamDefaultReadValueResult<Uint8Array> {
  if (result.done) {
    throw new Error("unexpected done");
  }
  if (result.value.byteLength !== expectedByteLength) {
    throw new Error(`expected ${expectedByteLength}, but ${result.value.byteLength}`);
  }
}

export function aesCtrDecrypt(readableStream: ReadableStream<Uint8Array>, password: string, pbkdf2Options: { iterations: number, hash: "SHA-256" } ): ReadableStream<Uint8Array> {
  const reader = new ReadableStreamSizedReader(readableStream.getReader());
  let salt: Uint8Array;
  let cryptoKey: CryptoKey;
  let counter: Uint8Array;
  return new ReadableStream({
    async start(ctrl) {
      const Salted__ = await reader.read(8);
      throwIfUnexpectedLength(Salted__, 8);
      const saltResult = await reader.read(8);
      throwIfUnexpectedLength(saltResult, 8);
      salt = saltResult.value;
      const keyAndIv = await deriveKeyAndIvByPbkdf2(salt, password, pbkdf2Options);
      cryptoKey = keyAndIv.cryptoKey;
      counter = keyAndIv.iv;
    },
    async pull(ctrl) {
      const result = await reader.read(blockByteSize);
      if (result.done) {
        ctrl.close();
        return;
      }
      const decrypted = await crypto.subtle.decrypt({ name: "AES-CTR", counter, length: ivBitSize }, cryptoKey, result.value);
      ctrl.enqueue(new Uint8Array(decrypted));
      // Increment counter destructively
      incrementCounter(counter);
    }
  })
}
