import {ReadableStreamSizedReader} from "readable-stream-sized-reader";
import {mergeUint8Arrays} from "binconv/dist/src/mergeUint8Arrays";

const ivBitSize = 128;
const blockByteSize = 16;

export async function deriveKeyAndIvByPbkdf2(params: { salt: Uint8Array, password: string, keyBits: 128 | 256, iterations: number, hash: HashAlgorithmIdentifier }): Promise<{ key: Uint8Array, iv: Uint8Array }> {
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(params.password),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );
  const keyIvBits = await window.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: params.salt,
      iterations: params.iterations,
      hash: params.hash
    },
    keyMaterial,
    params.keyBits + ivBitSize,
  );
  return {
    key: new Uint8Array(keyIvBits.slice(0, params.keyBits / 8)),
    iv: new Uint8Array(keyIvBits.slice(params.keyBits / 8)),
  }
}

function incrementCounter(counter: Uint8Array) {
  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i]++;
    if(counter[i] !== 0) break;
  }
}

export function aesCtrEncrypt(readableStream: ReadableStream<Uint8Array>, params: { salt: Uint8Array, key: Uint8Array, iv: Uint8Array } ): ReadableStream<Uint8Array> {
  const reader = new ReadableStreamSizedReader(readableStream.getReader());
  // Rest of read size for block size
  let restByteSize = blockByteSize;
  // Chunk which contains previous chunk
  const block: Uint8Array = new Uint8Array(blockByteSize);
  // Offset which current chunk should set on
  let blockOffset = 0;
  // Copy iv as counter because counter is updated destructively
  const counter = params.iv.slice();
  const cryptoKeyPromise = crypto.subtle.importKey("raw", params.key, { name: "AES-CTR" }, false, ["encrypt", "decrypt"]);
  return new ReadableStream({
    async pull(ctrl) {
      const result = await reader.read(restByteSize, false);
      if(result.done) {
        ctrl.close();
        return;
      }
      restByteSize -= result.value.byteLength;
      block.set(result.value, blockOffset);
      const cryptoKey = await cryptoKeyPromise;
      const blockEncrypted = await crypto.subtle.encrypt({ name: "AES-CTR", counter: counter, length: ivBitSize }, cryptoKey, block);
      const encrypted = blockEncrypted.slice(blockOffset, blockOffset + result.value.byteLength);
      blockOffset += result.value.byteLength;
      ctrl.enqueue(new Uint8Array(encrypted));
      // If one block encrypted
      if (restByteSize === 0) {
        // Increment counter destructively
        incrementCounter(counter);
        restByteSize = blockByteSize;
        blockOffset = 0;
      }
    }
  });
}

export function aesCtrEncryptWithPbkdf2(readableStream: ReadableStream<Uint8Array>, password: string, pbkdf2Options: { keyBits: 128 | 256, iterations: number, hash: HashAlgorithmIdentifier } ): ReadableStream<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(8));
  let key: Uint8Array;
  let iv: Uint8Array;
  let reader: ReadableStreamDefaultReader<Uint8Array>;

  return new ReadableStream({
    async start(ctrl) {
      ctrl.enqueue(mergeUint8Arrays([
        new TextEncoder().encode('Salted__'),
        salt
      ]));
      const keyAndIv = await deriveKeyAndIvByPbkdf2({
        salt,
        password,
        ...pbkdf2Options
      });
      key = keyAndIv.key;
      iv = keyAndIv.iv;
      reader = aesCtrEncrypt(readableStream, { salt, key, iv }).getReader();
    },
    async pull(ctrl) {
      const result = await reader.read();
      if (result.done) {
        ctrl.close();
        return;
      }
      ctrl.enqueue(result.value);
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

export function aesCtrDecrypt(readableStream: ReadableStream<Uint8Array>, params: { salt: Uint8Array, key: Uint8Array, iv: Uint8Array } ): ReadableStream<Uint8Array> {
  const reader = new ReadableStreamSizedReader(readableStream.getReader());
  const cryptoKeyPromise = crypto.subtle.importKey("raw", params.key, { name: "AES-CTR" }, false, ["encrypt", "decrypt"]);
  // Copy iv as counter because counter is updated destructively
  const counter: Uint8Array = params.iv.slice();
  // Rest of read size for block size
  let restByteSize = blockByteSize;
  // Block which contains previous chunk
  const block: Uint8Array = new Uint8Array(blockByteSize);
  // Offset which current chunk should set on
  let blockOffset = 0;
  return new ReadableStream({
    async pull(ctrl) {
      const result = await reader.read(restByteSize, false);
      if (result.done) {
        ctrl.close();
        return;
      }
      restByteSize -= result.value.byteLength;
      block.set(result.value, blockOffset);
      const cryptoKey = await cryptoKeyPromise;
      const blockDecrypted = await crypto.subtle.decrypt({ name: "AES-CTR", counter, length: ivBitSize }, cryptoKey, block);
      const decrypted = blockDecrypted.slice(blockOffset, blockOffset + result.value.byteLength);
      blockOffset += result.value.byteLength;
      ctrl.enqueue(new Uint8Array(decrypted));
      // If one block decrypted
      if (restByteSize === 0) {
        // Increment counter destructively
        incrementCounter(counter);
        restByteSize = blockByteSize;
        blockOffset = 0;
      }
    }
  });
}

export function aesCtrDecryptWithPbkdf2(encryptedReadableStream: ReadableStream<Uint8Array>, password: string, pbkdf2Options: { keyBits: 128 | 256, iterations: number, hash: HashAlgorithmIdentifier } ): ReadableStream<Uint8Array> {
  const encryptedReaderWithSalt = new ReadableStreamSizedReader(encryptedReadableStream.getReader());
  let salt: Uint8Array;
  let decryptedReader: ReadableStreamDefaultReader<Uint8Array>;
  return new ReadableStream({
    async start() {
      const Salted__ = await encryptedReaderWithSalt.read(8);
      throwIfUnexpectedLength(Salted__, 8);
      const saltResult = await encryptedReaderWithSalt.read(8);
      throwIfUnexpectedLength(saltResult, 8);
      salt = saltResult.value;
      const {key, iv} = await deriveKeyAndIvByPbkdf2({
        salt,
        password,
        ...pbkdf2Options
      });
      const encryptedReadableStream = new ReadableStream<Uint8Array>({
        async pull(ctrl) {
          const result = await encryptedReaderWithSalt.read();
          if (result.done) {
            ctrl.close();
            return;
          }
          ctrl.enqueue(result.value);
        }
      });
      decryptedReader = aesCtrDecrypt(encryptedReadableStream, { salt, key, iv }).getReader();
    },
    async pull(ctrl) {
      const result = await decryptedReader.read();
      if (result.done) {
        ctrl.close();
        return;
      }
      ctrl.enqueue(result.value);
    }
  });
}
