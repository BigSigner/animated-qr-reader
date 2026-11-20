import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import zlib from "node:zlib";
import QRCode from "qrcode";
import jsQR from "jsqr";
import gifenc from "gifenc";
import { BIP174_P2PKH_PSBT } from "../test/fixtures/bip174-p2pkh.mjs";

const { GIFEncoder } = gifenc;

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
const { Session, FragmentChooser, crc32, bytewordsEncode } = sandbox.QrAssemble;

const PSBT = BIP174_P2PKH_PSBT;
const SCALE = 10;
const BORDER = 4;
const DELAY = 1000;

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

function encodeFountain(message, maxFragmentLen) {
  const fragmentLen = nominal(message.length, 10, maxFragmentLen);
  const fragments = partition(message, fragmentLen);
  const checksum = crc32(message);
  const chooser = new FragmentChooser(fragments.length, checksum);
  let seq = 0;
  return {
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

function chunks(text, size) {
  const parts = [];
  for (let offset = 0; offset < text.length; offset += size) parts.push(text.slice(offset, offset + size));
  return parts;
}

function base36(value) {
  return value.toString(36).toUpperCase().padStart(2, "0");
}

function framesFor(name) {
  if (name === "ur") {
    const encoder = encodeFountain(cborBytes(PSBT), 140);
    const frames = [];
    const session = new Session();
    while (!session.result && frames.length < 40) {
      const part = encoder.next();
      frames.push(`UR:CRYPTO-PSBT/${part.seqNum}-${part.seqLen}/${bytewordsEncode(cborPart(part)).toUpperCase()}`);
      session.add(frames[frames.length - 1]);
    }
    return frames;
  }
  if (name === "bbqr") {
    const body = PSBT.toString("hex").toUpperCase();
    const parts = chunks(body, 280);
    return parts.map((part, index) => `B$HP${base36(parts.length)}${base36(index)}${part}`);
  }
  if (name === "specter") {
    const parts = chunks(PSBT.toString("base64"), 200);
    return parts.map((part, index) => `p${index + 1}of${parts.length} ${part}`);
  }
  if (name === "legacy-ur") {
    const parts = chunks(bytewordsEncode(PSBT), 280);
    return parts.map((part, index) => `UR:BYTES/${index + 1}OF${parts.length}/TESTGIF/${part}`);
  }
  if (name === "bigsigner") {
    const parts = chunks(zlib.gzipSync(PSBT).toString("base64"), 220);
    const lead = " ".repeat(parts.length + 1);
    return parts.map((part, index) => lead + part + " ".repeat(index));
  }
  throw new Error(name);
}

function draw(text, size) {
  const qr = QRCode.create(text, { errorCorrectionLevel: "M" });
  const modules = qr.modules.size;
  const pixels = (modules + BORDER * 2) * SCALE;
  const index = new Uint8Array(size * size);
  const rgba = new Uint8ClampedArray(size * size * 4);
  const origin = Math.floor((size - pixels) / 2);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const mx = Math.floor((x - origin) / SCALE) - BORDER;
      const my = Math.floor((y - origin) / SCALE) - BORDER;
      const black = mx >= 0 && my >= 0 && mx < modules && my < modules && qr.modules.get(mx, my);
      const offset = y * size + x;
      index[offset] = black ? 1 : 0;
      const color = black ? 0 : 255;
      rgba[offset * 4] = color;
      rgba[offset * 4 + 1] = color;
      rgba[offset * 4 + 2] = color;
      rgba[offset * 4 + 3] = 255;
    }
  }
  return { index, rgba, pixels };
}

function gifSize(texts) {
  let largest = 0;
  for (const text of texts) {
    const modules = QRCode.create(text, { errorCorrectionLevel: "M" }).modules.size;
    largest = Math.max(largest, (modules + BORDER * 2) * SCALE);
  }
  return largest;
}

function writeGif(name, texts) {
  const session = new Session();
  for (const text of texts) {
    const status = session.add(text);
    if (status.error) throw new Error(`${name}: ${status.error}`);
  }
  if (!session.result || session.filename !== "qr-scan.psbt") {
    throw new Error(`${name} did not produce a PSBT`);
  }
  if (Buffer.compare(Buffer.from(session.result), PSBT) !== 0) {
    throw new Error(`${name} decoded to a different file`);
  }

  const size = gifSize(texts);
  const gif = GIFEncoder();
  const palette = [[255, 255, 255], [0, 0, 0]];
  texts.forEach((text, frame) => {
    const image = draw(text, size);
    const code = jsQR(image.rgba, size, size);
    if (!code || code.data !== text) throw new Error(`${name} frame ${frame} did not read back`);
    gif.writeFrame(image.index, size, size, { palette: frame === 0 ? palette : null, delay: DELAY });
  });
  gif.finish();
  const path = join(root, "test/gifs", `${name}.gif`);
  writeFileSync(path, Buffer.from(gif.bytesView()));
  console.log(`${name}.gif`, texts.length, "frames", size + "px");
}

mkdirSync(join(root, "test/gifs"), { recursive: true });
for (const name of ["ur", "bbqr", "specter", "legacy-ur", "bigsigner"]) {
  writeGif(name, framesFor(name));
}
