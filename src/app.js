"use strict";

function cameraMessage(error) {
  if (error && error.name === "NotAllowedError") {
    return "The browser did not allow the camera. You can allow it in the browser settings.";
  }
  if (error && error.name === "NotFoundError") {
    return "No camera was found.";
  }
  if (!window.isSecureContext) {
    return "This browser blocks the camera for a file opened from disk. Serve that folder with python3 -m http.server, as described above.";
  }
  return "The camera did not start.";
}

function byteCount(size) {
  const digits = String(size).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return digits + (size === 1 ? " byte" : " bytes");
}

function readerComponent() {
  let session = new QrAssemble.Session();
  let stream = null;
  let timer = 0;
  let audio = null;

  return {
    cameraOn: false,
    cameraError: "",
    headline: "0",
    kicker: "",
    detail: "Point the camera at the animated code.",
    missing: "",
    percent: 0,
    showBar: false,
    showProgress: false,
    complete: false,
    error: "",
    notice: "",
    filename: "",
    scanned: 0,
    torchOn: false,
    torchAvailable: false,

    pull() {
      const status = session.view(false);
      const preview = status.notice.indexOf("once more") !== -1;
      this.scanned = status.scanned;
      this.complete = status.complete;
      this.error = status.error || "";
      this.notice = status.notice || "";
      this.filename = status.filename || "";
      this.showProgress = this.cameraOn || status.scanned > 0 || status.complete || !!status.error || !!status.notice;
      this.showBar = !!status.total;
      this.percent = status.total ? Math.min(100, Math.round((status.have / status.total) * 100)) : 0;
      if (status.total) this.headline = status.have + " of " + status.total;
      else if (preview) this.headline = "1 read";
      else if (status.scanned) this.headline = String(status.scanned);
      else this.headline = "0";
      if (status.format === "ur" && status.total) this.kicker = "Parts recovered";
      else if (status.total) this.kicker = "QR codes";
      else this.kicker = "";
      if (status.complete) {
        this.detail = status.label + " · " + byteCount(status.size);
      } else if (status.format === "ur" && status.total) {
        this.detail = status.scanned + " QR codes read · " + status.label;
      } else if (status.label) {
        this.detail = status.label;
      } else {
        this.detail = "Point the camera at the animated code.";
      }
      const missing = status.missing;
      if (!missing.length || status.complete) this.missing = "";
      else if (missing.length > 24) this.missing = "Still need " + missing.length + " QR codes";
      else this.missing = "Still need " + missing.join(", ");
      if (status.complete && this.cameraOn) this.closeCamera();
    },

    feed(text, bytes) {
      const status = session.add(bytes ? { text: text, bytes: bytes } : text);
      this.pull();
      if (status.fresh) this.beep();
    },

    beep() {
      try {
        if (navigator.vibrate) navigator.vibrate(20);
        audio = audio || new AudioContext();
        if (audio.state === "suspended") audio.resume();
        const oscillator = audio.createOscillator();
        const gain = audio.createGain();
        oscillator.frequency.value = 880;
        gain.gain.value = 0.045;
        oscillator.connect(gain);
        gain.connect(audio.destination);
        oscillator.start();
        oscillator.stop(audio.currentTime + 0.05);
      } catch (_error) {
        /* A missing speaker does not affect the scan. */
      }
    },

    async openCamera() {
      this.cameraError = "";
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        this.cameraError = "This browser has no camera.";
        return;
      }
      this.closeCamera();
      const attempts = [
        {
          audio: false,
          video: {
            facingMode: { ideal: "environment" },
            width: { ideal: 1280 },
            height: { ideal: 720 },
          },
        },
        { audio: false, video: true },
      ];
      for (let index = 0; index < attempts.length; index++) {
        try {
          stream = await navigator.mediaDevices.getUserMedia(attempts[index]);
        } catch (error) {
          if (error && error.name === "OverconstrainedError") continue;
          this.cameraError = cameraMessage(error);
          this.closeCamera();
          return;
        }
        const playing = await this.attachStream(stream);
        const last = index === attempts.length - 1;
        if (playing && (last || !(await pictureIsBlank(this.$refs.video)))) {
          this.cameraError = "";
          this.scan();
          return;
        }
        stream.getTracks().forEach((track) => track.stop());
        stream = null;
      }
      this.cameraError = "The camera picture did not start.";
      this.closeCamera();
    },

    async attachStream(next) {
      this.cameraOn = true;
      this.pull();
      // The preview is display:none until this update is painted. Playing
      // while it is hidden leaves a black picture and a frame size of zero,
      // so the scan never sees a code.
      await this.$nextTick();
      await painted();
      const video = this.$refs.video;
      if (!video) return false;
      video.muted = true;
      video.playsInline = true;
      video.srcObject = next;
      try {
        await video.play();
      } catch (_error) {
        return false;
      }
      if (!(await framesArrive(video))) return false;
      const track = next.getVideoTracks()[0];
      try {
        const capabilities = track.getCapabilities ? track.getCapabilities() : {};
        this.torchAvailable = !!(capabilities && capabilities.torch);
      } catch (_error) {
        this.torchAvailable = false;
      }
      return true;
    },

    closeCamera() {
      this.cameraOn = false;
      this.torchOn = false;
      this.torchAvailable = false;
      window.clearTimeout(timer);
      if (stream) {
        stream.getTracks().forEach((track) => track.stop());
        stream = null;
      }
      if (this.$refs.video) this.$refs.video.srcObject = null;
    },

    scan() {
      if (!this.cameraOn) return;
      const video = this.$refs.video;
      if (video && video.readyState >= 2 && video.videoWidth) {
        const scale = Math.min(1, 900 / Math.max(video.videoWidth, video.videoHeight));
        const width = Math.max(1, Math.round(video.videoWidth * scale));
        const height = Math.max(1, Math.round(video.videoHeight * scale));
        const canvas = this.$refs.canvas;
        if (canvas.width !== width) canvas.width = width;
        if (canvas.height !== height) canvas.height = height;
        const context = canvas.getContext("2d", { willReadFrequently: true });
        context.drawImage(video, 0, 0, width, height);
        const pixels = context.getImageData(0, 0, width, height);
        const code = jsQR(pixels.data, width, height, { inversionAttempts: "attemptBoth" });
        if (code) this.feed(code.data, code.binaryData);
      }
      if (this.cameraOn) timer = window.setTimeout(() => this.scan(), 90);
    },

    async toggleTorch() {
      if (!stream) return;
      const next = !this.torchOn;
      try {
        await stream.getVideoTracks()[0].applyConstraints({ advanced: [{ torch: next }] });
        this.torchOn = next;
      } catch (_error) {
        this.torchOn = false;
        this.torchAvailable = false;
      }
    },

    restart() {
      session = new QrAssemble.Session();
      this.pull();
    },

    downloadFile() {
      if (!session.result) return;
      saveBlob(new Blob([session.result], { type: "application/octet-stream" }), session.filename);
    },

    downloadPage() {
      const source = window.__pageSource || "<!DOCTYPE html>\n" + document.documentElement.outerHTML;
      saveBlob(new Blob([source], { type: "text/html" }), "animated-qr-reader.html");
    },
  };
}

async function pictureIsBlank(video) {
  await new Promise((resolve) => window.setTimeout(resolve, 350));
  if (!video || !video.videoWidth) return true;
  const sample = document.createElement("canvas");
  sample.width = 32;
  sample.height = 32;
  const context = sample.getContext("2d", { willReadFrequently: true });
  context.drawImage(video, 0, 0, 32, 32);
  const pixels = context.getImageData(0, 0, 32, 32).data;
  let total = 0;
  for (let i = 0; i < pixels.length; i += 4) total += pixels[i] + pixels[i + 1] + pixels[i + 2];
  return total / (32 * 32) < 3;
}

function painted() {
  return new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(resolve));
  });
}

function framesArrive(video) {
  if (video.videoWidth > 0) return Promise.resolve(true);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (forced) => {
      if (settled || (!forced && video.videoWidth <= 0)) return;
      settled = true;
      window.clearTimeout(timer);
      video.removeEventListener("loadeddata", onFrame);
      video.removeEventListener("resize", onFrame);
      resolve(video.videoWidth > 0);
    };
    const onFrame = () => finish(false);
    const timer = window.setTimeout(() => finish(true), 1500);
    video.addEventListener("loadeddata", onFrame);
    video.addEventListener("resize", onFrame);
  });
}

function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

document.addEventListener("alpine:init", () => {
  // Alpine dispatches this before it changes the document. The copy has to be
  // taken here: a script after Alpine runs too late, because Alpine starts in
  // the microtask between the two scripts.
  if (!window.__pageSource) {
    window.__pageSource = "<!DOCTYPE html>\n" + document.documentElement.outerHTML;
  }
  Alpine.data("reader", readerComponent);
});
