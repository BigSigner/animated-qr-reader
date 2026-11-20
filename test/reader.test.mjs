import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { BIP174_P2PKH_PSBT } from "./fixtures/bip174-p2pkh.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sandbox = {
  console,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  Uint16Array,
  Uint32Array,
  Int16Array,
  Int32Array,
  DataView,
  ArrayBuffer,
  BigInt,
  Map,
  Set,
  Number,
  Math,
  atob,
  btoa,
  Error,
  TypeError,
};
vm.createContext(sandbox);
vm.runInContext(readFileSync(join(root, "node_modules/pako/dist/pako_inflate.min.js"), "utf8"), sandbox);
vm.runInContext(readFileSync(join(root, "src/reader.js"), "utf8"), sandbox);

const {
  Session,
  FountainDecoder,
  FragmentChooser,
  Xoshiro256,
  crc32,
  sha256,
  bytewordsEncode,
  bytewordsDecode,
  BYTEWORDS,
} = sandbox.QrAssemble;

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function same(actual, expected) {
  assert.equal(hex(actual), hex(expected));
}

function concat(parts) {
  return Buffer.concat(parts.map((part) => Buffer.from(part)));
}

function cborUint(value) {
  if (value < 24) return Uint8Array.of(value);
  if (value < 256) return Uint8Array.of(0x18, value);
  if (value < 65536) return Uint8Array.of(0x19, value >> 8, value & 255);
  return Uint8Array.of(0x1a, value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
}

function cborHead(major, value) {
  const info = new Uint8Array(cborUint(value));
  info[0] = (info[0] & 31) | (major << 5);
  return info;
}

function cborBytes(data) {
  return concat([cborHead(2, data.length), data]);
}

function cborText(text) {
  const data = Buffer.from(text, "utf8");
  return concat([cborHead(3, data.length), data]);
}

function cborPart(part) {
  return concat([
    cborHead(4, 5),
    cborUint(part.seqNum),
    cborUint(part.seqLen),
    cborUint(part.messageLen),
    cborUint(part.checksum),
    cborBytes(part.data),
  ]);
}

function nominal(messageLen, minLen, maxLen) {
  const maxCount = Math.floor(messageLen / minLen);
  let fragmentLen = messageLen;
  for (let count = 1; count <= maxCount; count++) {
    fragmentLen = Math.ceil(messageLen / count);
    if (fragmentLen <= maxLen) break;
  }
  return fragmentLen;
}

function partition(message, fragmentLen) {
  const fragments = [];
  for (let offset = 0; offset < message.length; offset += fragmentLen) {
    const fragment = new Uint8Array(fragmentLen);
    fragment.set(message.subarray(offset, Math.min(message.length, offset + fragmentLen)));
    fragments.push(fragment);
  }
  return fragments;
}

function encodeFountain(message, maxFragmentLen, firstSeq = 0) {
  const fragmentLen = nominal(message.length, 10, maxFragmentLen);
  const fragments = partition(message, fragmentLen);
  const checksum = crc32(message);
  const chooser = new FragmentChooser(fragments.length, checksum);
  let seq = firstSeq;
  return {
    seqLen: fragments.length,
    checksum,
    next() {
      seq = (seq + 1) >>> 0;
      const indexes = chooser.choose(seq);
      const data = new Uint8Array(fragmentLen);
      for (const index of indexes) {
        const fragment = fragments[index];
        for (let i = 0; i < fragmentLen; i++) data[i] ^= fragment[i];
      }
      return { seqNum: seq, seqLen: fragments.length, messageLen: message.length, checksum, data };
    },
  };
}

function describe(part) {
  return `seqNum:${part.seqNum}, seqLen:${part.seqLen}, messageLen:${part.messageLen}, checksum:${part.checksum}, data:${hex(part.data)}`;
}

function urFrame(type, part) {
  const words = bytewordsEncode(cborPart(part)).toUpperCase();
  return `UR:${type.toUpperCase()}/${part.seqNum}-${part.seqLen}/${words}`;
}

function base36(value) {
  return value.toString(36).toUpperCase().padStart(2, "0");
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function encodeBase32(bytes) {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(buffer >> bits) & 31];
    }
  }
  if (bits) out += BASE32[(buffer << (5 - bits)) & 31];
  return out;
}

test("checksums and the bytewords list match the UR specification", () => {
  assert.equal(BYTEWORDS.length, 256);
  assert.equal(crc32(Buffer.from("Wolf")), 0x598c84dc);
  assert.equal(
    hex(sha256(Buffer.from("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  );
  assert.equal(
    hex(sha256(new Uint8Array())),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  const payload = Buffer.from("the times 03/Jan/2009");
  same(bytewordsDecode(bytewordsEncode(payload)), payload);
  same(bytewordsDecode(bytewordsEncode(payload).toUpperCase()), payload);
  const decoded = bytewordsDecode("oyadgdhkwzdtfthptokigtvwnnjsqzcxknsktdhpyljeda");
  assert.ok(decoded.length > 0);
});

test("xoshiro256 matches the multipart UR test vector", () => {
  const rng = new Xoshiro256("Wolf");
  const numbers = [];
  for (let i = 0; i < 100; i++) numbers.push(Number(rng.next() % 100n));
  assert.deepEqual(numbers, [42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74, 40, 48, 77, 54, 88, 7, 5, 88, 37, 25, 82, 13, 69, 59, 30, 39, 11, 82, 19, 99, 45, 87, 30, 15, 32, 22, 89, 44, 92, 77, 29, 78, 4, 92, 44, 68, 92, 69, 1, 42, 89, 50, 37, 84, 63, 34, 32, 3, 17, 62, 40, 98, 82, 89, 24, 43, 85, 39, 15, 3, 99, 29, 20, 42, 27, 10, 85, 66, 50, 35, 69, 70, 70, 74, 30, 13, 72, 54, 11, 5, 70, 55, 91, 52, 10, 43, 43, 52]);
});

test("fountain parts match the published encoder and decode in any order", () => {
  const message = new Uint8Array(256);
  const rng = new Xoshiro256("Wolf");
  for (let i = 0; i < message.length; i++) message[i] = rng.nextByte();
  const encoder = encodeFountain(message, 30);
  const expected = [
    "seqNum:1, seqLen:9, messageLen:256, checksum:23570951, data:916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
    "seqNum:2, seqLen:9, messageLen:256, checksum:23570951, data:cba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a",
    "seqNum:3, seqLen:9, messageLen:256, checksum:23570951, data:8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f",
    "seqNum:4, seqLen:9, messageLen:256, checksum:23570951, data:965e25ee29039fdf8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3e",
    "seqNum:5, seqLen:9, messageLen:256, checksum:23570951, data:c4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f59",
    "seqNum:6, seqLen:9, messageLen:256, checksum:23570951, data:5e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff1",
    "seqNum:7, seqLen:9, messageLen:256, checksum:23570951, data:73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
    "seqNum:8, seqLen:9, messageLen:256, checksum:23570951, data:791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22",
    "seqNum:9, seqLen:9, messageLen:256, checksum:23570951, data:951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d0000000000",
    "seqNum:10, seqLen:9, messageLen:256, checksum:23570951, data:330f0f33a05eead4f331df229871bee733b50de71afd2e5a79f196de09",
    "seqNum:11, seqLen:9, messageLen:256, checksum:23570951, data:3b205ce5e52d8c24a52cffa34c564fa1af3fdffcd349dc4258ee4ee828",
    "seqNum:12, seqLen:9, messageLen:256, checksum:23570951, data:dd7bf725ea6c16d531b5f03254783803048ca08b87148daacd1cd7a006",
    "seqNum:13, seqLen:9, messageLen:256, checksum:23570951, data:760be7ad1c6187902bbc04f539b9ee5eb8ea6833222edea36031306c01",
    "seqNum:14, seqLen:9, messageLen:256, checksum:23570951, data:5bf4031217d2c3254b088fa7553778b5003632f46e21db129416f65b55",
    "seqNum:15, seqLen:9, messageLen:256, checksum:23570951, data:73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
    "seqNum:16, seqLen:9, messageLen:256, checksum:23570951, data:b8546ebfe2048541348910267331c643133f828afec9337c318f71b7df",
    "seqNum:17, seqLen:9, messageLen:256, checksum:23570951, data:23dedeea74e3a0fb052befabefa13e2f80e4315c9dceed4c8630612e64",
    "seqNum:18, seqLen:9, messageLen:256, checksum:23570951, data:d01a8daee769ce34b6b35d3ca0005302724abddae405bdb419c0a6b208",
    "seqNum:19, seqLen:9, messageLen:256, checksum:23570951, data:3171c5dc365766eff25ae47c6f10e7de48cfb8474e050e5fe997a6dc24",
    "seqNum:20, seqLen:9, messageLen:256, checksum:23570951, data:e055c2433562184fa71b4be94f262e200f01c6f74c284b0dc6fae6673f",
  ];
  const parts = [];
  for (let i = 0; i < expected.length; i++) {
    const part = encoder.next();
    assert.equal(describe(part), expected[i]);
    parts.push(part);
  }

  const simple = new FountainDecoder();
  for (const index of [8, 0, 4, 2, 1, 3, 7, 6, 5]) simple.receive(parts[index]);
  same(simple.result, message);

  const mixed = new FountainDecoder();
  const fountain = encodeFountain(message, 30, 100);
  let status = "ok";
  for (let i = 0; i < 400 && !mixed.result; i++) status = mixed.receive(fountain.next());
  assert.notEqual(status, "bad-checksum");
  same(mixed.result, message);
});

test("UR frames reassemble a PSBT and other payloads", () => {
  const psbt = BIP174_P2PKH_PSBT;
  const single = new Session();
  single.add("ur:crypto-psbt/" + bytewordsEncode(cborBytes(psbt)));
  assert.equal(single.filename, "qr-scan.psbt");
  same(single.result, psbt);
  assert.equal(single.have, 1);
  assert.equal(single.total, 1);

  const cbor = cborBytes(psbt);
  const encoder = encodeFountain(cbor, 120);
  const frames = [];
  for (let i = 0; i < encoder.seqLen; i++) frames.push(urFrame("crypto-psbt", encoder.next()));
  const session = new Session();
  frames.slice().reverse().forEach((frame, index) => {
    const status = session.add(frame);
    assert.equal(status.fresh, true);
    assert.equal(status.label, "UR · crypto-psbt");
    assert.equal(status.total, encoder.seqLen);
    assert.equal(status.scanned, index + 1);
    if (index < frames.length - 1) assert.equal(status.complete, false);
  });
  assert.equal(session.add(frames[0]).fresh, false);
  same(session.result, psbt);
  assert.equal(session.filename, "qr-scan.psbt");

  const text = new Session();
  text.add("UR:BYTES/" + bytewordsEncode(cborText("hello, wallet")).toUpperCase());
  assert.equal(text.filename, "qr-scan.txt");
  assert.equal(Buffer.from(text.result).toString(), "hello, wallet");

  const binary = new Session();
  binary.add("ur:bytes/" + bytewordsEncode(cborBytes(Uint8Array.of(0, 255, 10))));
  assert.equal(binary.filename, "qr-scan.bin");
  same(binary.result, Uint8Array.of(0, 255, 10));
});

test("BBQr joins hex, base32, and raw deflate parts", () => {
  const psbt = BIP174_P2PKH_PSBT;
  const hexBody = psbt.toString("hex").toUpperCase();
  const chunks = [hexBody.slice(0, 16), hexBody.slice(16)];
  const session = new Session();
  chunks.forEach((chunk, index) => {
    session.add(`b$HP${base36(chunks.length)}${base36(index)}${chunk.toLowerCase()}`);
  });
  assert.equal(session.filename, "qr-scan.psbt");
  same(session.result, psbt);
  assert.equal(session.missing().join(","), "");

  const text = Buffer.from("a signed note, with a comma");
  const encoded = encodeBase32(text);
  const pieces = [];
  for (let offset = 0; offset < encoded.length; offset += 16) pieces.push(encoded.slice(offset, offset + 16));
  const base32 = new Session();
  for (let index = pieces.length - 1; index >= 0; index--) {
    base32.add(`B$2U${base36(pieces.length)}${base36(index)}${pieces[index]}`);
  }
  assert.equal(base32.filename, "qr-scan.txt");
  assert.equal(Buffer.from(base32.result).toString(), text.toString());

  const compressed = zlib.deflateRawSync(BIP174_P2PKH_PSBT, { windowBits: 10 });
  const packed = encodeBase32(compressed);
  const zParts = [packed.slice(0, 16), packed.slice(16)];
  const zlibSession = new Session();
  zlibSession.add(`B$ZP${base36(2)}${base36(1)}${zParts[1]}`);
  assert.equal(zlibSession.have, 1);
  assert.equal(zlibSession.missing().join(","), "1");
  zlibSession.add(`B$ZP${base36(2)}${base36(0)}${zParts[0]}`);
  same(zlibSession.result, BIP174_P2PKH_PSBT);
});

test("Specter and legacy UR parts can arrive in any order", () => {
  const psbt = BIP174_P2PKH_PSBT;
  const body = psbt.toString("base64");
  const parts = [body.slice(0, 8), body.slice(8, 16), body.slice(16)];
  const specter = new Session();
  [2, 0, 1].forEach((index) => {
    specter.add(`p${index + 1}of${parts.length} ${parts[index]}`);
  });
  assert.equal(specter.label, "Specter");
  assert.equal(specter.filename, "qr-scan.psbt");
  same(specter.result, psbt);

  const words = bytewordsEncode(psbt);
  const legacyParts = [words.slice(0, 20), words.slice(20, 40), words.slice(40)];
  const legacy = new Session();
  legacyParts.forEach((part, index) => {
    legacy.add(`UR:BYTES/${legacyParts.length - index}OF${legacyParts.length}/AbC123/${legacyParts[legacyParts.length - 1 - index]}`);
  });
  same(legacy.result, psbt);
  assert.equal(legacy.filename, "qr-scan.psbt");

  const descriptor = new Session();
  descriptor.add("p2of2 \"descriptor\"");
  descriptor.add("p1of2 {\"label\":");
  assert.equal(Buffer.from(descriptor.result).toString(), "{\"label\":\"descriptor\"");
  assert.equal(descriptor.filename, "qr-scan.txt");
});

test("BigSigner reads spaced gzip parts in any order", () => {
  function spaced(bytes, size) {
    const encoded = zlib.gzipSync(bytes).toString("base64");
    const chunks = [];
    for (let offset = 0; offset < encoded.length; offset += size) chunks.push(encoded.slice(offset, offset + size));
    const lead = " ".repeat(chunks.length + 1);
    return chunks.map((chunk, index) => lead + chunk + " ".repeat(index));
  }

  const text = Buffer.from("hello, BigSigner");
  const textSession = new Session();
  const textParts = spaced(text, 12);
  for (let index = textParts.length - 1; index >= 0; index--) textSession.add(textParts[index]);
  assert.equal(textSession.label, "BigSigner");
  assert.equal(textSession.have, textParts.length);
  assert.equal(Buffer.from(textSession.result).toString(), "hello, BigSigner");
  assert.equal(textSession.filename, "qr-scan.txt");

  const psbt = BIP174_P2PKH_PSBT;
  const psbtSession = new Session();
  spaced(psbt, 18).reverse().forEach((part) => psbtSession.add(part));
  assert.equal(psbtSession.filename, "qr-scan.psbt");
  same(psbtSession.result, psbt);

  const binary = new Session();
  spaced(Buffer.from([0, 1, 2, 255]), 8).forEach((part) => binary.add(part));
  assert.equal(binary.filename, "qr-scan.bin");

  const single = new Session();
  single.add(spaced(Buffer.from("one"), 500)[0]);
  assert.equal(Buffer.from(single.result).toString(), "one");
  assert.equal(single.total, 1);
});

test("a single QR is saved once its type is known", () => {
  const psbt = BIP174_P2PKH_PSBT;
  const base64 = new Session();
  const status = base64.add(psbt.toString("base64"));
  assert.equal(status.complete, true);
  assert.equal(base64.filename, "qr-scan.psbt");
  same(base64.result, psbt);

  const hexSession = new Session();
  hexSession.add(psbt.toString("hex"));
  same(hexSession.result, psbt);

  const plain = new Session();
  const first = plain.add("a descriptor wsh(sortedmulti(2,xpub))");
  assert.equal(first.complete, false);
  assert.equal(first.notice, "Read that code once more to confirm.");
  plain.add("a descriptor wsh(sortedmulti(2,xpub))");
  assert.equal(plain.filename, "qr-scan.txt");
  assert.equal(plain.scanned, 1);

  const replaced = new Session();
  replaced.add("first code");
  replaced.add("second code");
  assert.equal(replaced.result, null);
  replaced.add("second code");
  assert.equal(Buffer.from(replaced.result).toString(), "second code");

  const binary = new Session();
  const bytes = Uint8Array.of(0, 255, 3);
  binary.add({ text: "\u0000\u00ff\u0003", bytes });
  binary.add({ text: "\u0000\u00ff\u0003", bytes });
  assert.equal(binary.filename, "qr-scan.bin");
  same(binary.result, bytes);
});

test("a different sequence does not replace the one being scanned", () => {
  const body = BIP174_P2PKH_PSBT.toString("hex").toUpperCase();
  const session = new Session();
  session.add(`B$HP0200${body.slice(0, 32)}`);
  session.add("B$HT0300AAAA");
  assert.equal(session.error, null);
  assert.equal(session.have, 1);
  assert.match(session.notice, /different sequence/);
  session.add(`B$HP0201${body.slice(32)}`);
  assert.equal(session.filename, "qr-scan.psbt");
  same(session.result, BIP174_P2PKH_PSBT);
});
