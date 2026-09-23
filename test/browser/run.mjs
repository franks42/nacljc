#!/usr/bin/env node
// Headless Chromium check: Scittle code in test/browser/index.html runs the
// known-answer vectors against libsodium.js loaded from a <script> tag.
//
// Usage: node run.mjs [lib]
//   lib — optional libsodium.js browser build: a URL, or a local file path
//         (served under /local-lib/). Default: jsdelivr, libsodium.js 0.8.4.
// Prerequisite (one-time): npm install && npx playwright install chromium
// Or set CHROME_PATH to an installed Chrome/Chromium to skip Playwright's
// browser download (CI does this: the download stalled on runners).

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { chromium } from "playwright";

const ROOT = new URL("../..", import.meta.url).pathname;
const TIMEOUT_MS = 60_000;
const libArg = process.argv[2];
const localLib = libArg && !/^https?:/.test(libArg) ? resolve(libArg) : null;
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript" };

const server = createServer(async (req, res) => {
  const path = normalize(new URL(req.url, "http://localhost").pathname);
  const file = path === "/local-lib/sodium.js" && localLib ? localLib
             : path.includes("..") ? null : join(ROOT, path);
  try {
    const data = await readFile(file);
    res.writeHead(200, { "Content-Type": TYPES[extname(file)] || "text/plain; charset=utf-8",
                         "Cache-Control": "no-store" });
    res.end(data);
  } catch {
    res.writeHead(404); res.end();
  }
});
await new Promise(r => server.listen(0, "127.0.0.1", r));

let browser;
try {
  const base = `http://127.0.0.1:${server.address().port}`;
  const lib = localLib ? `${base}/local-lib/sodium.js` : libArg;
  const url = `${base}/test/browser/index.html` + (lib ? `?lib=${encodeURIComponent(lib)}` : "");
  browser = await chromium.launch({
    headless: true,
    ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}),
  });
  const page = await browser.newPage();
  const done = new Promise(r => {
    page.on("console", m => {
      const t = m.text();
      if (!t.startsWith("[") ) console.log(t);
      if (t.startsWith("DONE")) r(t);
    });
    page.on("pageerror", e => r("DONE pageerror " + e.message));
    setTimeout(() => r("DONE timeout"), TIMEOUT_MS).unref();
  });
  await page.goto(url);
  const result = await done;
  if (result !== "DONE 0 failed") process.exitCode = 1;
} catch (e) {
  console.error("runner error:", e.message);
  process.exitCode = 1;
} finally {
  if (browser) await browser.close();
  server.close();
}
