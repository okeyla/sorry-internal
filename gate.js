// =====================================================
// 密碼鎖：輸入密碼 → 解密 data.enc.js → 執行原本的 script.js
// 網頁裡沒有存密碼，也沒有明碼連結；密碼錯就解不開。
// =====================================================
(function () {
  const KEY_STORE = "unlockKey"; // 同一個分頁重新整理時不用再輸入
  const gate = document.getElementById("gate");
  const gateForm = document.getElementById("gateForm");
  const gatePw = document.getElementById("gatePw");
  const gateMsg = document.getElementById("gateMsg");

  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

  // 由密碼推導出 AES 金鑰
  async function deriveKey(password) {
    const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: fromB64(ENC.salt), iterations: ENC.iter, hash: "SHA-256" },
      baseKey, { name: "AES-GCM", length: 256 }, true, ["decrypt"]
    );
  }

  // 解密成功就執行原本的程式，並解除鎖定
  async function unlock(key) {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(ENC.iv) }, key, fromB64(ENC.ct));
    const s = document.createElement("script");
    s.textContent = new TextDecoder().decode(plain);
    document.body.appendChild(s);
    document.body.classList.remove("locked");
    gate.remove();
  }

  gateForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    gateMsg.textContent = "解鎖中…";
    try {
      const key = await deriveKey(gatePw.value);
      await unlock(key);
      try { sessionStorage.setItem(KEY_STORE, toB64(await crypto.subtle.exportKey("raw", key))); } catch (err) {}
    } catch (err) {
      gateMsg.textContent = "密碼錯誤";
      gatePw.select();
    }
  });

  // 同一分頁之前解鎖過，就直接解開
  (async function () {
    let saved = null;
    try { saved = sessionStorage.getItem(KEY_STORE); } catch (err) {}
    if (!saved) return gatePw.focus();
    try {
      const key = await crypto.subtle.importKey("raw", fromB64(saved), "AES-GCM", false, ["decrypt"]);
      await unlock(key);
    } catch (err) {
      try { sessionStorage.removeItem(KEY_STORE); } catch (e) {}
      gatePw.focus();
    }
  })();
})();
