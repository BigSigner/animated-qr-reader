# Animated QR Reader

One HTML file that opens the camera, reads a sequence of QR codes, and saves the file they contain. The finished page does not need a network connection.

## Build

```bash
npm install
npm test
npm run build
```

The camera, the decoders, Alpine.js, jsQR, pako, and the Tailwind CSS are inside `dist/index.html`. **Download this page** on that page saves another copy of the same file.

Opening the file directly often blocks the camera. Serve the folder instead:

```bash
cd dist
python3 -m http.server
```

Then open http://127.0.0.1:8000/ . A downloaded copy is served the same way from its own folder, at http://127.0.0.1:8000/animated-qr-reader.html . Paste still works when the page is opened straight from the file. Keep the spaces: BigSigner stores the part order in them.

## Formats

Parts can arrive in any order.

- UR, including fountain codes such as `crypto-psbt`, from SeedSigner, Foundation Passport, Keystone, Blockstream Jade, Sparrow, and Krux.
- BBQr from COLDCARD Q, Sparrow, and Nunchuk, in hex, base32, or zlib.
- Specter `p1ofN` from Specter Desktop, Specter DIY, and Krux.
- Legacy `UR:BYTES/1ofN` from older Specter and BTCPay.
- BigSigner: gzip, then base64. The leading spaces are the part count plus one, and the trailing spaces are the part index.
- One code: a PSBT in binary, base64, base43, or hex. Any other plain code is kept after the same code is read twice.

A PSBT is saved as `.psbt`. Other text is saved as `.txt`. Other bytes are saved as `.bin`. The page shows how many codes are in hand and how many belong in the sequence.

## Notices

Alpine.js is MIT. jsQR is Apache-2.0. pako is MIT and Zlib. Tailwind CSS is MIT. Source Sans 3, Source Serif 4, and Source Code Pro are SIL Open Font License. The Bytewords list and the UR fountain design are from Blockchain Commons, under BSD-2-Clause-Patent. This reader is MIT, copyright 2026 BigSigner.
