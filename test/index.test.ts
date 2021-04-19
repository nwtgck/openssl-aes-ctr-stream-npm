import * as assert from 'power-assert';
import {
  aesCtrDecrypt,
  aesCtrDecryptWithPbkdf2,
  aesCtrEncrypt,
  aesCtrEncryptWithPbkdf2,
  deriveKeyAndIvByPbkdf2
} from "../src";
import {readableStreamToUint8Array, base64ToUint8Array, uint8ArrayToString} from "binconv";

function hexStringToUint8Array(hexString: String): Uint8Array {
  if(hexString.length % 2 !== 0) {
    throw new Error(`length of hex string should be even number but ${hexString.length}`);
  }
  const arr = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hexString.substr(i * 2, 2), 16);
  }
  return arr;
}

describe('aes-ctr', () => {
  // OpenSSL 1.1.1h
  //  command: echo "hello, world" | openssl aes-256-ctr -S AC2FDA1FA716E4B3 -K 95C2692DFAEA430A7F3712BE22E786384EA3E29EDA7ECDA52CECFC3AF327F916 -iv C7215956D07AE3D880A18BAA046EE598 -a
  it('should encrypt', async () => {
    const plainReadableStream = new ReadableStream({
      start(ctrl) {
        ctrl.enqueue(new TextEncoder().encode("hello, world\n"));
        ctrl.close();
      }
    })
    const salt = hexStringToUint8Array("AC2FDA1FA716E4B3");
    const key = hexStringToUint8Array('95C2692DFAEA430A7F3712BE22E786384EA3E29EDA7ECDA52CECFC3AF327F916');
    const iv = hexStringToUint8Array('C7215956D07AE3D880A18BAA046EE598');
    const encryptedReadableStream = aesCtrEncrypt(plainReadableStream, { salt, key, iv });
    const encrypted: Uint8Array = await readableStreamToUint8Array(encryptedReadableStream);
    const expected: Uint8Array = base64ToUint8Array('wc70/4v9cC2D8QrMUg==');
    assert.deepStrictEqual(encrypted, expected);
  });

  // OpenSSL 1.1.1h
  //  command: echo "wc70/4v9cC2D8QrMUg==" | openssl aes-256-ctr -d -S AC2FDA1FA716E4B3 -K 95C2692DFAEA430A7F3712BE22E786384EA3E29EDA7ECDA52CECFC3AF327F916 -iv C7215956D07AE3D880A18BAA046EE598 -a
  it('should decrypt', async () => {
    const plainReadableStream = new ReadableStream({
      start(ctrl) {
        ctrl.enqueue(base64ToUint8Array("wc70/4v9cC2D8QrMUg=="));
        ctrl.close();
      }
    })
    const salt = hexStringToUint8Array("AC2FDA1FA716E4B3");
    const key = hexStringToUint8Array('95C2692DFAEA430A7F3712BE22E786384EA3E29EDA7ECDA52CECFC3AF327F916');
    const iv = hexStringToUint8Array('C7215956D07AE3D880A18BAA046EE598');
    const decryptedReadableStream = aesCtrDecrypt(plainReadableStream, { salt, key, iv });
    const decrypted: string = uint8ArrayToString(await readableStreamToUint8Array(decryptedReadableStream));
    const expected: string = "hello, world\n";
    assert.deepStrictEqual(decrypted, expected);
  });

  it('should decrypt when 128-bit key is derived from PBKDF2', async () => {
    const encryptedReadableStream = new ReadableStream({
      start(ctrl) {
        // OpenSSL 1.1.1h
        // generated by: echo "hello, world" | openssl aes-128-ctr -p -pbkdf2 -md sha256 -iter 100000 -pass pass:1234 -a
        ctrl.enqueue(base64ToUint8Array("U2FsdGVkX19kKECUdeI1JBp93ySDysKQlQcLj/s="));
        ctrl.close();
      }
    });
    const pbkdf2Options = {
      password: "1234",
      keyBits: 128,
      iterations: 100000,
      hash: "SHA-256",
    } as const;
    const decryptedReadableStream = aesCtrDecryptWithPbkdf2(encryptedReadableStream, pbkdf2Options);
    const decryptedText: string = new TextDecoder().decode(await readableStreamToUint8Array(decryptedReadableStream));
    assert.strictEqual(decryptedText, "hello, world\n");
  });

  it('should decrypt when 256-bit key is derived from PBKDF2', async () => {
    const encryptedReadableStream = new ReadableStream({
      start(ctrl) {
        // OpenSSL 1.1.1h
        // generated by: echo "hello, world" | openssl aes-256-ctr -p -pbkdf2 -md sha256 -iter 100000 -pass pass:1234 -a
        ctrl.enqueue(base64ToUint8Array("U2FsdGVkX18EPpkR74ZBC37ge0DsKGUWv0AAm3M="));
        ctrl.close();
      }
    });
    const pbkdf2Options = {
      password: "1234",
      keyBits: 256,
      iterations: 100000,
      hash: "SHA-256",
    } as const;
    const decryptedReadableStream = aesCtrDecryptWithPbkdf2(encryptedReadableStream, pbkdf2Options);
    const decryptedText: string = new TextDecoder().decode(await readableStreamToUint8Array(decryptedReadableStream));
    assert.strictEqual(decryptedText, "hello, world\n");
  });

  it('should encrypt and decrypt when key is derived from PBKDF2', async () => {
    const plainReadableStream = new ReadableStream({
      start: (controller) => {
        controller.enqueue(new TextEncoder().encode("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde"));
        controller.enqueue(new TextEncoder().encode("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCD"));
        controller.enqueue(new TextEncoder().encode("01234567890123456789012345678901234567890123"));
        controller.close();
      }
    });
    const pbkdf2Options = {
      password: "1234",
      keyBits: 256,
      iterations: 100000,
      hash: "SHA-256",
    } as const;
    const encryptedReadableStream = aesCtrEncryptWithPbkdf2(plainReadableStream, pbkdf2Options);
    const decryptedReadableStream = aesCtrDecryptWithPbkdf2(encryptedReadableStream, pbkdf2Options);
    const decryptedText: string = new TextDecoder().decode(await readableStreamToUint8Array(decryptedReadableStream));
    assert.strictEqual(decryptedText, 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdeABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCD01234567890123456789012345678901234567890123');
  });
});


describe('deriveKeyAndIvByPbkdf2', () => {
  it('should derive key as the same as openssl does where 128-bit key -S AC2FDA1FA716E4B3 -md sha1 -iter 100000 -pass pass:1234', async () => {
    const {key, iv} = await deriveKeyAndIvByPbkdf2({
      salt: hexStringToUint8Array("AC2FDA1FA716E4B3"),
      password: "1234",
      keyBits: 128,
      iterations: 100000,
      hash: "SHA-1",
    });
    // expected ones found by: echo | openssl aes-128-ctr -p -pbkdf2 -S AC2FDA1FA716E4B3 -md sha1 -iter 100000 -pass pass:1234 -a
    const expectedKey = hexStringToUint8Array("3B7DB00C636E600EE566C1A6A8E49DD8");
    const expectedIv = hexStringToUint8Array("C250CA14C1EBFDD4E359AA304E5085A0");
    assert.deepStrictEqual(key, expectedKey);
    assert.deepStrictEqual(iv, expectedIv);
  });

  it('should derive key as the same as openssl does where 128-bit key -S AC2FDA1FA716E4B3 -md sha512 -iter 100000 -pass pass:1234', async () => {
    const {key, iv} = await deriveKeyAndIvByPbkdf2( {
      salt: hexStringToUint8Array("AC2FDA1FA716E4B3"),
      password: "1234",
      keyBits: 128,
      iterations: 100000,
      hash: "SHA-512",
    });
    // expected ones found by: echo | openssl aes-128-ctr -p -pbkdf2 -S AC2FDA1FA716E4B3 -md sha512 -iter 100000 -pass pass:1234 -a
    const expectedKey = hexStringToUint8Array("3549BB0C39237346E2BA4519E30EBFB9");
    const expectedIv = hexStringToUint8Array("A83430DA81C505A5071F4363104B5372");
    assert.deepStrictEqual(key, expectedKey);
    assert.deepStrictEqual(iv, expectedIv);
  });
});
