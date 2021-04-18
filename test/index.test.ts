import * as assert from 'power-assert';
import {aesCtrDecrypt, aesCtrEncrypt} from "../src";
import {readableStreamToUint8Array} from "binconv";

describe('aes-ctr', () => {
  it('should encrypt and decrypt', async () => {
    const plainReadableStream =  new ReadableStream({
      start: (controller) => {
        controller.enqueue(new TextEncoder().encode("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde"));
        controller.enqueue(new TextEncoder().encode("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCD"));
        controller.enqueue(new TextEncoder().encode("01234567890123456789012345678901234567890123"));
        controller.close();
      }
    });
    const password = "1234";
    const pbkdf2Options = {
      iterations: 100000,
      hash: "SHA-256",
    } as const;
    const encryptedReadableStream = aesCtrEncrypt(plainReadableStream, password, pbkdf2Options);
    const decryptedReadableStream = aesCtrDecrypt(encryptedReadableStream, password, pbkdf2Options)
    const decryptedText: string = new TextDecoder().decode(await readableStreamToUint8Array(decryptedReadableStream));
    assert.strictEqual(decryptedText, 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdeABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCD01234567890123456789012345678901234567890123');
  });
});
