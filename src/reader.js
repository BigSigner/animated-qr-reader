"use strict";

// Assemble an animated QR sequence into one file.
//
// UR (BCUR) uses fountain codes: any enough frames rebuild the message.
// BBQr, Specter p1ofN, legacy UR:BYTES/MofN, and BigSigner are ordered parts.
// BigSigner marks each part with spaces: leading spaces are the part count
// plus one, and trailing spaces are the part index, starting at zero. The
// body is gzip, then base64. Parts may arrive in any order.

const MAX_PARTS = 2000;
const MAX_BYTES = 1500000;
const BYTEWORDS = (
  "able acid also apex aqua arch atom aunt " +
  "away axis back bald barn belt beta bias " +
  "blue body brag brew bulb buzz calm cash " +
  "cats chef city claw code cola cook cost " +
  "crux curl cusp cyan dark data days deli " +
  "dice diet door down draw drop drum dull " +
  "duty each easy echo edge epic even exam " +
  "exit eyes fact fair fern figs film fish " +
  "fizz flap flew flux foxy free frog fuel " +
  "fund gala game gear gems gift girl glow " +
  "good gray grim guru gush gyro half hang " +
  "hard hawk heat help high hill holy hope " +
  "horn huts iced idea idle inch inky into " +
  "iris iron item jade jazz join jolt jowl " +
  "judo jugs jump junk jury keep keno kept " +
  "keys kick kiln king kite kiwi knob lamb " +
  "lava lazy leaf legs liar limp lion list " +
  "logo loud love luau luck lung main many " +
  "math maze memo menu meow mild mint miss " +
  "monk nail navy need news next noon note " +
  "numb obey oboe omit onyx open oval owls " +
  "paid part peck play plus poem pool pose " +
  "puff puma purr quad quiz race ramp real " +
  "redo rich road rock roof ruby ruin runs " +
  "rust safe saga scar sets silk skew slot " +
  "soap solo song stub surf swan taco task " +
  "taxi tent tied time tiny toil tomb toys " +
  "trip tuna twin ugly undo unit urge user " +
  "vast very veto vial vibe view visa void " +
  "vows wall wand warm wasp wave waxy webs " +
  "what when whiz wolf work yank yawn yell " +
  "yoga yurt zaps zero zest zinc zone zoom"
).split(" ");

const WORD_INDEX = new Int16Array(26 * 26);
WORD_INDEX.fill(-1);
for (let i = 0; i < BYTEWORDS.length; i++) {
  const word = BYTEWORDS[i];
  WORD_INDEX[(word.charCodeAt(3) - 97) * 26 + (word.charCodeAt(0) - 97)] = i;
}

const BBQR_NAMES = {
  P: "PSBT",
  T: "transaction",
  J: "JSON",
  C: "CBOR",
  U: "text",
  B: "binary",
  X: "executable",
};

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE43 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:";
const MASK64 = (1n << 64n) - 1n;

function concat(parts) {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function hexOf(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

function u32be(bytes, offset) {
  return (
    bytes[offset] * 0x1000000 +
    ((bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3])
  ) >>> 0;
}

function writeU32(bytes, offset, value) {
  bytes[offset] = value >>> 24;
  bytes[offset + 1] = value >>> 16;
  bytes[offset + 2] = value >>> 8;
  bytes[offset + 3] = value & 255;
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

const SHA_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function sha256(data) {
  const bytes = data instanceof Uint8Array ? data : Uint8Array.from(data);
  const bitLen = bytes.length * 8;
  const padded = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  view.setUint32(padded.length - 4, bitLen >>> 0);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + SHA_K[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((value, index) => outView.setUint32(index * 4, value));
  return out;
}

function rotl64(x, k) {
  const bits = BigInt(k);
  return ((x << bits) | (x >> (64n - bits))) & MASK64;
}

class Xoshiro256 {
  constructor(seed) {
    const bytes = typeof seed === "string" ? new TextEncoder().encode(seed) : seed;
    const digest = sha256(bytes);
    this.state = [0n, 0n, 0n, 0n];
    for (let i = 0; i < 4; i++) {
      let value = 0n;
      for (let byte = 0; byte < 8; byte++) value = (value << 8n) | BigInt(digest[i * 8 + byte]);
      this.state[i] = value;
    }
  }

  next() {
    const state = this.state;
    const result = (rotl64((state[1] * 5n) & MASK64, 7) * 9n) & MASK64;
    const t = (state[1] << 17n) & MASK64;
    state[2] = (state[2] ^ state[0]) & MASK64;
    state[3] = (state[3] ^ state[1]) & MASK64;
    state[1] = (state[1] ^ state[2]) & MASK64;
    state[0] = (state[0] ^ state[3]) & MASK64;
    state[2] = (state[2] ^ t) & MASK64;
    state[3] = rotl64(state[3], 45);
    return result;
  }

  nextDouble() {
    return Number(this.next()) / 2 ** 64;
  }

  nextIntBelow(count) {
    return Math.trunc(this.nextDouble() * count);
  }

  nextByte() {
    return this.nextIntBelow(256);
  }
}

class RandomSampler {
  constructor(probabilities) {
    const count = probabilities.length;
    let sum = 0;
    for (const probability of probabilities) sum += probability;
    const scaled = probabilities.map((probability) => (probability * count) / sum);
    const small = [];
    const large = [];
    for (let i = count - 1; i >= 0; i--) {
      if (scaled[i] < 1) small.push(i);
      else large.push(i);
    }
    const probs = new Array(count);
    const aliases = new Array(count);
    while (small.length && large.length) {
      const less = small.pop();
      const more = large.pop();
      probs[less] = scaled[less];
      aliases[less] = more;
      scaled[more] = scaled[more] + scaled[less] - 1;
      if (scaled[more] < 1) small.push(more);
      else large.push(more);
    }
    while (large.length) probs[large.pop()] = 1;
    while (small.length) probs[small.pop()] = 1;
    this.probs = probs;
    this.aliases = aliases;
  }

  next(rng) {
    const r1 = rng.nextDouble();
    const r2 = rng.nextDouble();
    let i = Math.trunc(this.probs.length * r1);
    if (i >= this.probs.length) i = this.probs.length - 1;
    return r2 < this.probs[i] ? i : this.aliases[i];
  }
}

class FragmentChooser {
  constructor(seqLen, checksum) {
    const probabilities = [];
    for (let i = 1; i <= seqLen; i++) probabilities.push(1 / i);
    this.sampler = new RandomSampler(probabilities);
    this.indexes = [];
    for (let i = 0; i < seqLen; i++) this.indexes.push(i);
    this.seqLen = seqLen;
    this.checksum = checksum >>> 0;
  }

  choose(seqNum) {
    if (seqNum >= 1 && seqNum <= this.seqLen) return new Set([seqNum - 1]);
    const seed = new Uint8Array(8);
    writeU32(seed, 0, seqNum >>> 0);
    writeU32(seed, 4, this.checksum);
    const rng = new Xoshiro256(seed);
    const degree = this.sampler.next(rng) + 1;
    const remaining = this.indexes.slice();
    const chosen = new Set();
    while (chosen.size < degree) {
      const index = rng.nextIntBelow(remaining.length);
      chosen.add(remaining.splice(index, 1)[0]);
    }
    return chosen;
  }
}

function setKey(indexes) {
  return Array.from(indexes).sort((a, b) => a - b).join(",");
}

function isStrictSubset(inner, outer) {
  if (inner.size >= outer.size) return false;
  for (const index of inner) if (!outer.has(index)) return false;
  return true;
}

function xorBytes(left, right) {
  const out = new Uint8Array(left.length);
  for (let i = 0; i < left.length; i++) out[i] = left[i] ^ right[i];
  return out;
}

class FountainDecoder {
  constructor() {
    this.simple = new Map();
    this.mixed = new Map();
    this.queue = [];
    this.received = new Set();
    this.expected = null;
    this.messageLen = null;
    this.checksum = null;
    this.fragmentLen = null;
    this.chooser = null;
    this.result = null;
    this.error = null;
    this.processed = 0;
  }

  get recovered() {
    return this.received.size;
  }

  receive(part) {
    if (this.result || this.error) return "done";
    if (!this._valid(part)) return "mismatch";
    if (!this.chooser) this.chooser = new FragmentChooser(part.seqLen, part.checksum);
    const indexes = this.chooser.choose(part.seqNum);
    this.queue.push({ indexes, data: part.data });
    this._drain();
    this.processed += 1;
    if (this.error) return "bad-checksum";
    if (this.result) return "complete";
    return "ok";
  }

  _valid(part) {
    if (
      !Number.isInteger(part.seqLen) ||
      part.seqLen < 1 ||
      part.seqLen > MAX_PARTS ||
      !Number.isInteger(part.messageLen) ||
      part.messageLen < 0 ||
      part.messageLen > MAX_BYTES ||
      !(part.data instanceof Uint8Array) ||
      part.data.length < 1 ||
      part.data.length > 8000
    ) {
      return false;
    }
    if (this.expected == null) {
      this.expected = part.seqLen;
      this.messageLen = part.messageLen;
      this.checksum = part.checksum >>> 0;
      this.fragmentLen = part.data.length;
      return true;
    }
    return (
      this.expected === part.seqLen &&
      this.messageLen === part.messageLen &&
      this.checksum === (part.checksum >>> 0) &&
      this.fragmentLen === part.data.length
    );
  }

  _drain() {
    while (!this.result && !this.error && this.queue.length) {
      const part = this.queue.shift();
      if (part.indexes.size === 1) this._simple(part);
      else this._mixed(part);
    }
  }

  _reduce(part, by) {
    if (!isStrictSubset(by.indexes, part.indexes)) return part;
    const indexes = new Set(part.indexes);
    for (const index of by.indexes) indexes.delete(index);
    return { indexes, data: xorBytes(part.data, by.data) };
  }

  _reduceMixed(by) {
    const reduced = [];
    for (const part of this.mixed.values()) reduced.push(this._reduce(part, by));
    this.mixed = new Map();
    for (const part of reduced) {
      if (part.indexes.size === 1) this.queue.push(part);
      else this.mixed.set(setKey(part.indexes), part);
    }
  }

  _simple(part) {
    const index = part.indexes.values().next().value;
    if (this.received.has(index)) return;
    this.simple.set(index, part);
    this.received.add(index);
    if (this.received.size === this.expected) {
      const fragments = [];
      for (let i = 0; i < this.expected; i++) fragments.push(this.simple.get(i).data);
      const joined = concat(fragments).subarray(0, this.messageLen);
      if (crc32(joined) !== this.checksum) {
        this.error = "The checksum does not match. Start over and scan the code again.";
        return;
      }
      this.result = joined;
      return;
    }
    this._reduceMixed(part);
  }

  _mixed(part) {
    const key = setKey(part.indexes);
    if (this.mixed.has(key)) return;
    let reduced = part;
    for (const other of this.simple.values()) reduced = this._reduce(reduced, other);
    for (const other of this.mixed.values()) reduced = this._reduce(reduced, other);
    if (reduced.indexes.size === 1) {
      this.queue.push(reduced);
      return;
    }
    this._reduceMixed(reduced);
    this.mixed.set(setKey(reduced.indexes), reduced);
  }
}

function decodeToken(token) {
  const x = token.charCodeAt(0) - 97;
  const y = token.charCodeAt(token.length === 4 ? 3 : 1) - 97;
  if (x < 0 || y < 0 || x > 25 || y > 25) throw new Error("bytewords");
  const value = WORD_INDEX[y * 26 + x];
  if (value < 0) throw new Error("bytewords");
  if (token.length === 4 && BYTEWORDS[value] !== token) throw new Error("bytewords");
  return value;
}

function bytewordsEncode(bytes) {
  const checksum = crc32(bytes);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const word = BYTEWORDS[bytes[i]];
    out += word[0] + word[3];
  }
  for (let shift = 24; shift >= 0; shift -= 8) {
    const word = BYTEWORDS[(checksum >>> shift) & 255];
    out += word[0] + word[3];
  }
  return out;
}

function bytewordsDecode(text) {
  const raw = text.trim().toLowerCase();
  let values;
  if (/^[a-z]+$/.test(raw)) {
    if (raw.length < 8 || raw.length % 2 !== 0) throw new Error("bytewords");
    values = new Uint8Array(raw.length / 2);
    for (let i = 0; i < values.length; i++) values[i] = decodeToken(raw.slice(i * 2, i * 2 + 2));
  } else {
    const words = raw.split(/[\s-]+/).filter(Boolean);
    if (words.length < 5) throw new Error("bytewords");
    values = new Uint8Array(words.length);
    for (let i = 0; i < words.length; i++) {
      if (words[i].length !== 4) throw new Error("bytewords");
      values[i] = decodeToken(words[i]);
    }
  }
  const body = values.subarray(0, -4);
  if (crc32(body) !== u32be(values, values.length - 4)) throw new Error("checksum");
  return new Uint8Array(body);
}

function readInfo(bytes, offset, info) {
  if (info < 24) return [info, offset];
  if (info === 24) return [bytes[offset], offset + 1];
  if (info === 25) return [(bytes[offset] << 8) | bytes[offset + 1], offset + 2];
  if (info === 26) return [u32be(bytes, offset), offset + 4];
  if (info === 27) {
    let value = 0n;
    for (let i = 0; i < 8; i++) value = (value << 8n) | BigInt(bytes[offset + i]);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("cbor");
    return [Number(value), offset + 8];
  }
  throw new Error("cbor");
}

function readCbor(bytes, offset) {
  const head = bytes[offset];
  const major = head >> 5;
  const info = head & 31;
  const [length, next] = readInfo(bytes, offset + 1, info);
  if (major === 0) return { value: length, offset: next };
  if (major === 1) return { value: -1 - length, offset: next };
  if (major === 2) return { value: bytes.slice(next, next + length), offset: next + length };
  if (major === 3) {
    return { value: new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(next, next + length)), offset: next + length };
  }
  if (major === 4) {
    const items = [];
    let cursor = next;
    for (let i = 0; i < length; i++) {
      const item = readCbor(bytes, cursor);
      items.push(item.value);
      cursor = item.offset;
    }
    return { value: items, offset: cursor };
  }
  if (major === 5) {
    let cursor = next;
    for (let i = 0; i < length; i++) {
      const key = readCbor(bytes, cursor);
      const value = readCbor(bytes, key.offset);
      cursor = value.offset;
    }
    return { value: undefined, offset: cursor };
  }
  if (major === 6) return readCbor(bytes, next);
  if (major === 7 && info < 24) return { value: info === 20 ? false : info === 21 ? true : null, offset: offset + 1 };
  throw new Error("cbor");
}

function unwrapCbor(bytes) {
  try {
    const decoded = readCbor(bytes, 0);
    if (decoded.offset !== bytes.length) return bytes;
    if (decoded.value instanceof Uint8Array) return decoded.value;
    if (typeof decoded.value === "string") return new TextEncoder().encode(decoded.value);
  } catch (error) {
    if (error && error.message !== "cbor") throw error;
  }
  return bytes;
}

function decodeFountainPart(bytes) {
  const decoded = readCbor(bytes, 0);
  if (!Array.isArray(decoded.value) || decoded.value.length < 5) throw new Error("part");
  const [seqNum, seqLen, messageLen, checksum, data] = decoded.value;
  if (!(data instanceof Uint8Array)) throw new Error("part");
  return {
    seqNum: seqNum >>> 0,
    seqLen,
    messageLen,
    checksum: checksum >>> 0,
    data,
  };
}

function isPsbt(bytes) {
  return bytes.length >= 5 &&
    bytes[0] === 0x70 && bytes[1] === 0x73 && bytes[2] === 0x62 && bytes[3] === 0x74 &&
    bytes[4] === 0xff;
}

function isAscii(bytes) {
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte !== 9 && byte !== 10 && byte !== 13 && (byte < 32 || byte > 126)) return false;
  }
  return true;
}

function fileName(bytes, hint) {
  const extension = hint === "psbt" || isPsbt(bytes) ? "psbt" : isAscii(bytes) ? "txt" : "bin";
  return "qr-scan." + extension;
}

function decodeHex(text) {
  if (text.length % 2 !== 0) throw new Error("hex");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) {
    const value = parseInt(text.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(value)) throw new Error("hex");
    out[i] = value;
  }
  return out;
}

function decodeBase32(text) {
  const remainder = text.length % 8;
  if (remainder === 1 || remainder === 3 || remainder === 6) throw new Error("base32");
  const out = new Uint8Array(Math.floor((text.length * 5) / 8));
  let input = 0;
  let output = 0;
  while (input < text.length) {
    const count = Math.min(8, text.length - input);
    let bits = 0n;
    for (let i = 0; i < count; i++) {
      const value = BASE32.indexOf(text[input + i]);
      if (value < 0) throw new Error("base32");
      bits = (bits << 5n) | BigInt(value);
    }
    bits <<= 5n * BigInt(8 - count);
    const produced = Math.min(5, out.length - output);
    for (let i = 0; i < 5; i++) {
      const byte = Number((bits >> BigInt(32 - 8 * i)) & 255n);
      if (i < produced) out[output + i] = byte;
      else if (byte !== 0) throw new Error("base32");
    }
    output += produced;
    input += count;
  }
  return out;
}

function decodeBase64(text) {
  const stripped = text.replace(/=+$/, "");
  if (stripped.length % 4 === 1) throw new Error("base64");
  const padded = stripped + "=".repeat((4 - (stripped.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function decodeBase43(text) {
  if (!text) return null;
  let value = 0n;
  for (const character of text) {
    const digit = BASE43.indexOf(character);
    if (digit < 0) return null;
    value = value * 43n + BigInt(digit);
  }
  if (value === 0n) return new Uint8Array([0]);
  const bytes = [];
  while (value > 0n) {
    bytes.push(Number(value & 255n));
    value >>= 8n;
  }
  bytes.reverse();
  return Uint8Array.from(bytes);
}

function psbtFromText(text) {
  const trimmed = text.trim();
  if (/^[0-9A-Fa-f]+$/.test(trimmed) && trimmed.length >= 10 && trimmed.length % 2 === 0) {
    if (trimmed.toLowerCase().startsWith("70736274ff")) return decodeHex(trimmed);
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) && trimmed.length >= 8) {
    try {
      const bytes = decodeBase64(trimmed);
      if (isPsbt(bytes)) return bytes;
    } catch (_error) {
      /* The text is not a PSBT. */
    }
  }
  const base43 = decodeBase43(trimmed);
  if (base43 && isPsbt(base43)) return base43;
  return null;
}

function gunzip(bytes) {
  if (!globalThis.pako) throw new Error("decompress");
  return pako.ungzip(bytes);
}

function inflateRaw(bytes) {
  if (!globalThis.pako) throw new Error("decompress");
  return pako.inflateRaw(bytes);
}

function parseSpaced(text) {
  const match = /^( {2,})([A-Za-z0-9+/]+={0,2})( *)$/.exec(text);
  if (!match) return null;
  const total = match[1].length - 1;
  const index = match[3].length;
  if (total < 1 || total > MAX_PARTS || index >= total || match[2].length > 8000) return null;
  return { total, index, body: match[2] };
}

function parseBbqr(text) {
  const trimmed = text.trim();
  if (!/^B\$/i.test(trimmed) || trimmed.length < 9) return null;
  const upper = trimmed.toUpperCase();
  const encoding = upper[2];
  const type = upper[3];
  if (!"H2Z".includes(encoding)) return null;
  if (!/^[0-9A-Z]{4}/.test(upper.slice(4, 8))) return null;
  const total = parseInt(upper.slice(4, 6), 36);
  const index = parseInt(upper.slice(6, 8), 36);
  if (!(total >= 1 && total <= 1295 && index >= 0 && index < total)) return null;
  return { encoding, type, total, index, body: upper.slice(8) };
}

function parseSpecter(text) {
  const match = /^p(\d+)of(\d+) ([\s\S]+)$/i.exec(text);
  if (!match) return null;
  const number = Number(match[1]);
  const total = Number(match[2]);
  if (!(total >= 1 && total <= MAX_PARTS && number >= 1 && number <= total)) return null;
  return { index: number - 1, total, body: match[3] };
}

function parseUr(text) {
  const match = /^ur:([a-z0-9-]+)\/([\s\S]+)$/i.exec(text.trim());
  if (!match) return null;
  const type = match[1].toLowerCase();
  const rest = match[2];
  const fountain = /^(\d+)-(\d+)\/([\s\S]+)$/.exec(rest);
  if (fountain) {
    return {
      kind: "fountain",
      type,
      seq: Number(fountain[1]),
      total: Number(fountain[2]),
      payload: fountain[3],
    };
  }
  const legacy = /^(\d+)of(\d+)\/([^/\s]+)\/([\s\S]+)$/i.exec(rest);
  if (legacy) {
    return {
      kind: "legacy",
      type,
      index: Number(legacy[1]) - 1,
      total: Number(legacy[2]),
      hash: legacy[3],
      payload: legacy[4],
    };
  }
  if (rest.includes("/")) return { kind: "invalid", type };
  return { kind: "single", type, payload: rest };
}

function decodeBbqrBody(encoding, body) {
  if (encoding === "H") return decodeHex(body);
  return decodeBase32(body);
}

class Session {
  constructor() {
    this.format = null;
    this.label = "";
    this.total = null;
    this.have = 0;
    this.scanned = 0;
    this.error = null;
    this.notice = "";
    this.filename = null;
    this.result = null;
    this.seen = new Set();
    this.parts = new Map();
    this.fountain = null;
    this.urType = null;
    this.meta = null;
    this.pending = null;
  }

  add(input) {
    if (this.result || this.error) return this.view(false);
    const text = typeof input === "string" ? input : (input && input.text != null ? String(input.text) : null);
    const bytes = input && input.bytes ? new Uint8Array(input.bytes) : null;
    const key = text != null ? "t\u0000" + text : "b\u0000" + hexOf(bytes || new Uint8Array());
    if (this.seen.has(key)) return this.view(false);

    try {
      const outcome = this._dispatch(text, bytes);
      if (outcome === "ignore") {
        this.seen.add(key);
        if (!this.notice) this.notice = "That QR code was skipped.";
        return this.view(false);
      }
      if (outcome === "pending") return this.view(true);
      this.seen.add(key);
      this.scanned += 1;
      this.notice = "";
      return this.view(true);
    } catch (error) {
      this.error = error && error.message === "decompress"
        ? "This file could not be decompressed."
        : "This sequence could not be read. Start over and scan it again.";
      return this.view(true);
    }
  }

  _dispatch(text, bytes) {
    if (this.format === "bbqr") return text != null && this._bbqr(text) ? "ok" : "ignore";
    if (this.format === "specter") return text != null && this._specter(text) ? "ok" : "ignore";
    if (this.format === "bigsigner") return text != null && this._bigsigner(text) ? "ok" : "ignore";
    if (this.format === "legacy") return text != null && this._legacy(text) ? "ok" : "ignore";
    if (this.format === "ur") return text != null && this._ur(text) ? "ok" : "ignore";
    if (this.format) return "ignore";

    if (text != null && this._bigsigner(text)) return "ok";
    if (text != null && /^ur:/i.test(text.trim())) {
      const parsed = parseUr(text);
      if (!parsed || parsed.kind === "invalid") return "ignore";
      if (parsed.kind === "legacy") return this._legacy(text) ? "ok" : "ignore";
      return this._ur(text) ? "ok" : "ignore";
    }
    if (text != null && this._bbqr(text)) return "ok";
    if (text != null && this._specter(text)) return "ok";

    const psbt = text != null ? psbtFromText(text) : null;
    if (psbt || (bytes && isPsbt(bytes))) {
      this._claim("single");
      this.label = "PSBT";
      this.total = 1;
      this.have = 1;
      this._finish(psbt || bytes, "psbt");
      return "ok";
    }
    return this._plain(text, bytes);
  }

  _claim(format) {
    this.pending = null;
    this.format = format;
  }

  _finish(bytes, hint) {
    const data = new Uint8Array(bytes);
    if (data.length > MAX_BYTES) {
      this.error = "This sequence is too large.";
      return;
    }
    this.result = data;
    this.filename = fileName(data, hint || (this.urType === "crypto-psbt" ? "psbt" : null));
    if (this.total == null) this.total = 1;
    this.have = this.total;
  }

  _takePart(index, total, body, label) {
    if (this.total == null) {
      this.total = total;
      this.label = label;
    } else if (this.total !== total) {
      this.notice = "Skipped a QR code from a different sequence.";
      return false;
    }
    if (this.parts.has(index)) {
      const previous = this.parts.get(index);
      if (previous !== body) this.notice = "Skipped a QR code that does not match this sequence.";
      return false;
    }
    this.parts.set(index, body);
    this.have = this.parts.size;
    return true;
  }

  _bigsigner(text) {
    const part = parseSpaced(text);
    if (!part) return false;
    if (this.format && this.format !== "bigsigner") return false;
    if (part.total === 1) {
      let file;
      try {
        file = gunzip(decodeBase64(part.body));
      } catch (_error) {
        return false;
      }
      this._claim("bigsigner");
      this.label = "BigSigner";
      this.total = 1;
      this.have = 1;
      this._finish(file, null);
      return true;
    }
    this._claim("bigsigner");
    if (!this._takePart(part.index, part.total, part.body, "BigSigner")) return false;
    if (this.have === this.total) this._finishBigsigner();
    return true;
  }

  _finishBigsigner() {
    let encoded = "";
    for (let i = 0; i < this.total; i++) encoded += this.parts.get(i);
    let compressed;
    try {
      compressed = decodeBase64(encoded);
      this._finish(gunzip(compressed), null);
    } catch (_error) {
      this.error = "This file could not be decompressed.";
    }
  }

  _bbqr(text) {
    const part = parseBbqr(text);
    if (!part) return false;
    if (!this.meta) this.meta = { encoding: part.encoding, type: part.type };
    else if (this.meta.encoding !== part.encoding || this.meta.type !== part.type) {
      this.notice = "Skipped a QR code from a different sequence.";
      return false;
    }
    this._claim("bbqr");
    const name = BBQR_NAMES[part.type];
    if (!this._takePart(part.index, part.total, part.body, name ? "BBQr · " + name : "BBQr")) return false;
    if (this.have === this.total) this._finishBbqr();
    return true;
  }

  _finishBbqr() {
    try {
      const pieces = [];
      for (let i = 0; i < this.total; i++) pieces.push(decodeBbqrBody(this.meta.encoding, this.parts.get(i)));
      let file = concat(pieces);
      if (this.meta.encoding === "Z") file = inflateRaw(file);
      this._finish(file, this.meta.type === "P" ? "psbt" : null);
    } catch (_error) {
      this.error = "This BBQr sequence could not be read. Start over and scan it again.";
    }
  }

  _specter(text) {
    const part = parseSpecter(text);
    if (!part) return false;
    this._claim("specter");
    if (!this._takePart(part.index, part.total, part.body, "Specter")) return false;
    if (this.have === this.total) this._finishNumbered(false);
    return true;
  }

  _legacy(text) {
    const parsed = parseUr(text);
    if (!parsed || parsed.kind !== "legacy") return false;
    if (parsed.total < 1 || parsed.index < 0) return false;
    if (!this.meta) this.meta = { hash: parsed.hash.toUpperCase(), type: parsed.type };
    else if (this.meta.hash !== parsed.hash.toUpperCase() || this.meta.type !== parsed.type || (this.total && this.total !== parsed.total)) {
      this.notice = "Skipped a QR code from a different sequence.";
      return false;
    }
    this._claim("legacy");
    if (!this._takePart(parsed.index, parsed.total, parsed.payload, "Legacy UR")) return false;
    if (this.have === this.total) this._finishNumbered(true);
    return true;
  }

  _finishNumbered(bytewords) {
    let joined = "";
    for (let i = 0; i < this.total; i++) joined += this.parts.get(i);
    if (bytewords) {
      try {
        const bytes = bytewordsDecode(joined);
        this._finish(bytes, isPsbt(bytes) ? "psbt" : null);
        return;
      } catch (_error) {
        /* Fall through to the joined text. */
      }
    }
    const psbt = psbtFromText(joined);
    if (psbt) {
      this._finish(psbt, "psbt");
      return;
    }
    this._finish(new TextEncoder().encode(joined), null);
  }

  _ur(text) {
    const parsed = parseUr(text);
    if (!parsed || parsed.kind === "legacy" || parsed.kind === "invalid") return false;
    if (parsed.kind === "single") {
      let message;
      try {
        message = unwrapCbor(bytewordsDecode(parsed.payload));
      } catch (_error) {
        return false;
      }
      this._claim("ur");
      this.urType = parsed.type;
      this.label = "UR · " + parsed.type;
      this.total = 1;
      this.have = 1;
      this._finish(message, parsed.type === "crypto-psbt" ? "psbt" : null);
      return true;
    }
    let part;
    try {
      part = decodeFountainPart(bytewordsDecode(parsed.payload));
    } catch (_error) {
      return false;
    }
    if (part.seqNum !== (parsed.seq >>> 0) || part.seqLen !== parsed.total) return false;
    if (!this.fountain) {
      this.fountain = new FountainDecoder();
      this.urType = parsed.type;
      this._claim("ur");
      this.label = "UR · " + parsed.type;
    } else if (this.urType !== parsed.type) {
      this.notice = "Skipped a QR code from a different sequence.";
      return false;
    }
    const outcome = this.fountain.receive(part);
    if (outcome === "mismatch") {
      this.notice = "Skipped a QR code from a different sequence.";
      return false;
    }
    this.total = this.fountain.expected;
    this.have = this.fountain.recovered;
    if (outcome === "bad-checksum") {
      this.error = this.fountain.error;
      return true;
    }
    if (outcome === "complete") {
      const file = unwrapCbor(this.fountain.result);
      this.have = this.total;
      this._finish(file, parsed.type === "crypto-psbt" ? "psbt" : null);
    }
    return true;
  }

  _plain(text, bytes) {
    const key = text != null ? text : hexOf(bytes || new Uint8Array());
    if (text != null && (/^ur:/i.test(text.trim()) || /^B\$/i.test(text.trim()) || /^p\d+of\d+ /i.test(text))) {
      this.notice = "That QR code was skipped.";
      return "ignore";
    }
    if (this.pending && this.pending.key === key) {
      this._claim("single");
      this.label = "QR code";
      this.total = 1;
      this.have = 1;
      this._finish(this._plainBytes(text, bytes), null);
      return "ok";
    }
    this.pending = { key };
    this.label = "QR code";
    this.notice = "Read that code once more to confirm.";
    return "pending";
  }

  _plainBytes(text, bytes) {
    if (bytes && !isUtf8(bytes)) return bytes;
    if (text != null) return new TextEncoder().encode(text);
    return bytes || new Uint8Array();
  }

  missing() {
    if (!this.total || this.result || this.format === "ur" || this.format === "single") return [];
    const missing = [];
    for (let i = 0; i < this.total; i++) if (!this.parts.has(i)) missing.push(i + 1);
    return missing;
  }

  view(fresh) {
    return {
      fresh,
      format: this.format,
      label: this.label,
      scanned: this.scanned,
      have: this.have,
      total: this.total,
      missing: this.missing(),
      complete: this.result != null,
      error: this.error,
      notice: this.notice,
      filename: this.filename,
      size: this.result ? this.result.length : 0,
    };
  }
}

function isUtf8(bytes) {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch (_error) {
    return false;
  }
}

globalThis.QrAssemble = {
  Session,
  FountainDecoder,
  FragmentChooser,
  Xoshiro256,
  crc32,
  sha256,
  bytewordsEncode,
  bytewordsDecode,
  BYTEWORDS,
};
