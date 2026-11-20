import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, "dist");
mkdirSync(dist, { recursive: true });

const cssPath = join(dist, "tailwind.css");
execFileSync(
  join(root, "node_modules/.bin/tailwindcss"),
  ["--input", join(root, "src/tailwind.css"), "--output", cssPath, "--minify"],
  { cwd: root, stdio: "inherit" },
);

function inline(path) {
  const source = readFileSync(join(root, path), "utf8").replace(/<\/script/gi, "<\\/script");
  return "<script>\n" + source + "\n</script>";
}

const css = embedFonts(readFileSync(cssPath, "utf8"), dist).replace(/<\/style/gi, "<\\/style");
rmSync(cssPath);

function embedFonts(css, fromDir) {
  return css.replace(/url\(([^)]+)\)/g, (match, raw) => {
    const spec = raw.trim().replace(/^['"]|['"]$/g, "");
    if (!/\.woff2?(?:$|[?#])/.test(spec) || spec.startsWith("data:")) return match;
    const file = join(fromDir, spec.split(/[?#]/)[0]);
    const type = file.endsWith(".woff2") ? "font/woff2" : "font/woff";
    const data = readFileSync(file).toString("base64");
    return `url("data:${type};base64,${data}")`;
  });
}

const scripts = [
  inline("node_modules/pako/dist/pako_inflate.min.js"),
  inline("node_modules/jsqr/dist/jsQR.js"),
  inline("src/reader.js"),
  inline("src/app.js"),
  inline("node_modules/alpinejs/dist/cdn.min.js"),
].join("\n");

const page = splice(splice(readFileSync(join(root, "src/page.html"), "utf8"), "<!--STYLES-->", "<style>\n" + css + "\n</style>"), "<!--SCRIPTS-->", scripts);
writeFileSync(join(dist, "index.html"), page);

function splice(page, marker, value) {
  const at = page.indexOf(marker);
  if (at < 0) throw new Error("Missing " + marker);
  // String.replace treats $$ in the replacement as one $, which stripped the
  // $ from Alpine's this.$refs and this.$nextTick.
  return page.slice(0, at) + value + page.slice(at + marker.length);
}
console.log("wrote dist/index.html", page.length);
