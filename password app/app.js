const storageKey = "kisisel-kasa-v2";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  salt: null,
  pinHash: null,
  key: null,
  data: { passwords: [], memories: [] },
};

const $ = (selector) => document.querySelector(selector);

const lockScreen = $("#lockScreen");
const appScreen = $("#appScreen");
const lockTitle = $("#lockTitle");
const lockCopy = $("#lockCopy");
const lockMessage = $("#lockMessage");
const pinInput = $("#pinInput");
const pinForm = $("#pinForm");

const randomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));
const toBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
const fromBase64 = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));

async function sha256(value) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toBase64(new Uint8Array(hash));
}

async function deriveKey(pin, salt) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptData(data) {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, state.key, encoder.encode(JSON.stringify(data)));
  return { iv: toBase64(iv), payload: toBase64(new Uint8Array(encrypted)) };
}

async function decryptData(record) {
  if (!record.vault) return { passwords: [], memories: [] };
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(record.vault.iv) },
    state.key,
    fromBase64(record.vault.payload),
  );
  return JSON.parse(decoder.decode(decrypted));
}

function readRecord() {
  const raw = localStorage.getItem(storageKey);
  return raw ? JSON.parse(raw) : null;
}

async function saveRecord() {
  const vault = await encryptData(state.data);
  localStorage.setItem(storageKey, JSON.stringify({
    salt: toBase64(state.salt),
    pinHash: state.pinHash,
    vault,
  }));
}

function configureLockCopy() {
  const record = readRecord();
  if (record) {
    lockTitle.textContent = "Kasanı aç";
    lockCopy.textContent = "Şifrelerin ve anıların bu cihazda kilitli. Devam etmek için PIN gir.";
  }
}

function showApp() {
  lockScreen.classList.add("hidden");
  appScreen.classList.remove("hidden");
  pinInput.value = "";
  lockMessage.textContent = "";
  renderAll();
}

function showLock() {
  appScreen.classList.add("hidden");
  lockScreen.classList.remove("hidden");
  pinInput.focus();
}

async function setupVault(pin) {
  state.salt = randomBytes(16);
  state.pinHash = await sha256(`${pin}:${toBase64(state.salt)}`);
  state.key = await deriveKey(pin, state.salt);
  await saveRecord();
  showApp();
}

async function unlockVault(pin, record) {
  state.salt = fromBase64(record.salt);
  const incomingHash = await sha256(`${pin}:${record.salt}`);
  if (incomingHash !== record.pinHash) {
    lockMessage.textContent = "PIN hatalı. Bir daha dene.";
    return;
  }

  try {
    state.pinHash = record.pinHash;
    state.key = await deriveKey(pin, state.salt);
    state.data = await decryptData(record);
    showApp();
  } catch {
    lockMessage.textContent = "Kasa açılamadı. PIN'i kontrol et.";
  }
}

pinForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const pin = pinInput.value.trim();
  if (pin.length < 4) {
    lockMessage.textContent = "PIN en az 4 haneli olmalı.";
    return;
  }

  const record = readRecord();
  if (record) {
    await unlockVault(pin, record);
  } else {
    await setupVault(pin);
  }
});

$("#lockButton").addEventListener("click", showLock);

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    tab.classList.add("active");
    $("#passwordsPanel").classList.toggle("hidden", tab.dataset.tab !== "passwords");
    $("#memoriesPanel").classList.toggle("hidden", tab.dataset.tab !== "memories");
  });
});

$("#showPasswordForm").addEventListener("click", () => $("#passwordForm").classList.toggle("hidden"));
$("#showMemoryForm").addEventListener("click", () => $("#memoryForm").classList.toggle("hidden"));

$("#passwordForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const item = {
    id: crypto.randomUUID(),
    site: $("#siteInput").value.trim(),
    user: $("#userInput").value.trim(),
    password: $("#passwordInput").value,
    note: $("#noteInput").value.trim(),
  };
  if (!item.site || !item.password) return;
  state.data.passwords.unshift(item);
  event.target.reset();
  event.target.classList.add("hidden");
  await saveRecord();
  renderPasswords();
});

$("#memoryForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const item = {
    id: crypto.randomUUID(),
    title: $("#memoryTitleInput").value.trim(),
    date: $("#memoryDateInput").value,
    text: $("#memoryTextInput").value.trim(),
  };
  if (!item.title || !item.text) return;
  state.data.memories.unshift(item);
  event.target.reset();
  event.target.classList.add("hidden");
  await saveRecord();
  renderMemories();
});

function renderPasswords() {
  const list = $("#passwordList");
  if (!state.data.passwords.length) {
    list.innerHTML = `<div class="empty">Henüz şifre eklenmedi.</div>`;
    return;
  }

  list.innerHTML = state.data.passwords.map((item) => `
    <article class="card">
      <div class="card-top">
        <div>
          <h4>${escapeHtml(item.site)}</h4>
          <p>${escapeHtml(item.user || "Kullanıcı adı yok")}</p>
        </div>
        <button class="ghost-button" type="button" data-delete-password="${item.id}">Sil</button>
      </div>
      <div class="secret-row">
        <p data-secret="${item.id}">••••••••</p>
        <button class="ghost-button" type="button" data-show-password="${item.id}">Göster</button>
      </div>
      ${item.note ? `<p class="card-note">${escapeHtml(item.note)}</p>` : ""}
    </article>
  `).join("");
}

function renderMemories() {
  const list = $("#memoryList");
  if (!state.data.memories.length) {
    list.innerHTML = `<div class="empty">Henüz anı eklenmedi.</div>`;
    return;
  }

  list.innerHTML = state.data.memories.map((item) => `
    <article class="card">
      <div class="card-top">
        <div>
          <h4>${escapeHtml(item.title)}</h4>
          <p>${item.date ? escapeHtml(formatDate(item.date)) : "Tarih yok"}</p>
        </div>
        <button class="ghost-button" type="button" data-delete-memory="${item.id}">Sil</button>
      </div>
      <p class="card-note">${escapeHtml(item.text)}</p>
    </article>
  `).join("");
}

function renderAll() {
  renderPasswords();
  renderMemories();
}

document.addEventListener("click", async (event) => {
  const showId = event.target.dataset.showPassword;
  const deletePasswordId = event.target.dataset.deletePassword;
  const deleteMemoryId = event.target.dataset.deleteMemory;

  if (showId) {
    const item = state.data.passwords.find((password) => password.id === showId);
    const field = document.querySelector(`[data-secret="${showId}"]`);
    if (!item || !field) return;
    const isHidden = field.textContent.includes("•");
    field.textContent = isHidden ? item.password : "••••••••";
    event.target.textContent = isHidden ? "Gizle" : "Göster";
  }

  if (deletePasswordId) {
    state.data.passwords = state.data.passwords.filter((item) => item.id !== deletePasswordId);
    await saveRecord();
    renderPasswords();
  }

  if (deleteMemoryId) {
    state.data.memories = state.data.memories.filter((item) => item.id !== deleteMemoryId);
    await saveRecord();
    renderMemories();
  }
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  })[char]);
}

function formatDate(value) {
  return new Intl.DateTimeFormat("tr-TR", { day: "numeric", month: "long", year: "numeric" }).format(new Date(value));
}

configureLockCopy();
