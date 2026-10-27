// =====================================================
// 加密工具：把 src/script.js（明碼，不上傳）加密成 data.enc.js
// 用法：node encrypt.mjs   → 輸入兩次密碼
// 修改連結後，改 src/script.js，再跑一次這個指令即可。
// =====================================================
import { readFile, writeFile } from "node:fs/promises";
import { webcrypto as crypto } from "node:crypto";

const ITERATIONS = 310000; // PBKDF2 次數，越大越難暴力猜密碼

// 讀取密碼（終端機時不顯示輸入的字元）
let pending = ""; // 一次收到多行時，留給下一次讀
function askPassword(prompt) {
  return new Promise(function (resolve) {
    const stdin = process.stdin;
    process.stdout.write(prompt);
    let input = "";
    let done = false;
    function finish() {
      done = true;
      if (stdin.isTTY) stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);
      process.stdout.write("\n");
      resolve(input);
    }
    function onData(chunk) {
      pending += chunk;
      while (pending) {
        const c = pending[0];
        pending = pending.slice(1);
        if (c === "\r" || c === "\n") {
          if (c === "\r" && pending[0] === "\n") pending = pending.slice(1);
          return finish();
        } else if (c === "\u0003") {
          process.exit(1); // Ctrl+C
        } else if (c === "\u007f" || c === "\b") {
          input = input.slice(0, -1);
        } else {
          input += c;
        }
      }
    }
    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.setEncoding("utf8");
    stdin.on("data", onData);
    if (pending) onData("");
    if (!done) stdin.resume();
  });
}

const b64 = (buf) => Buffer.from(buf).toString("base64");

const pw1 = await askPassword("請輸入密碼：");
const pw2 = await askPassword("再輸入一次：");
if (!pw1) { console.error("密碼不能是空的"); process.exit(1); }
if (pw1 !== pw2) { console.error("兩次密碼不一樣，請重來"); process.exit(1); }

const plain = await readFile(new URL("./src/script.js", import.meta.url), "utf8");
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));

const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw1), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
  baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
);
const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plain));

const out = "// 自動產生，請勿手動修改（由 encrypt.mjs 產生）\nwindow.ENC = " + JSON.stringify({
  iter: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct)
}) + ";\n";
await writeFile(new URL("./data.enc.js", import.meta.url), out);
console.log("完成：已產生 data.enc.js");
