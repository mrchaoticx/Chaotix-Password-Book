/* ----------------------
    CRYPTO HELPERS
---------------------- */

async function deriveKey(masterPassword, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(masterPassword),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptData(key, data) {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        enc.encode(data)
    );

    return { iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(encrypted)) };
}

async function decryptData(key, encryptedObject) {
    const iv = new Uint8Array(encryptedObject.iv);
    const ciphertext = new Uint8Array(encryptedObject.ciphertext);

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
}

/* ----------------------
    APP LOGIC
---------------------- */

let passwordBook = [];
let masterKey = null;
let salt = null;

async function login() {
    const pw = document.getElementById("masterPassword").value;
    if (!pw) return alert("Enter a password!");

    const stored = localStorage.getItem("encryptedPasswordBook");

    // FIRST TIME USER → generate salt
    if (!stored) {
        salt = crypto.getRandomValues(new Uint8Array(16));
        masterKey = await deriveKey(pw, salt);
        localStorage.setItem("salt", JSON.stringify(Array.from(salt)));
        passwordBook = [];
    } else {
        // Returning user
        salt = new Uint8Array(JSON.parse(localStorage.getItem("salt")));
        masterKey = await deriveKey(pw, salt);

        try {
            const parsed = JSON.parse(stored);
            const decrypted = await decryptData(masterKey, parsed);
            passwordBook = JSON.parse(decrypted);
        } catch (e) {
            alert("❌ Wrong master password!");
            return;
        }
    }

    document.getElementById("loginDiv").style.display = "none";
    document.getElementById("app").style.display = "block";
    displayEntries();
}

async function saveEncrypted() {
    const encrypted = await encryptData(masterKey, JSON.stringify(passwordBook));
    localStorage.setItem("encryptedPasswordBook", JSON.stringify(encrypted));
}

function displayEntries() {
    const ul = document.getElementById("entryList");
    ul.innerHTML = "";
    passwordBook.forEach(entry => {
        const li = document.createElement("li");
        li.textContent = `${entry.site} | ${entry.username} | ${entry.password}`;
        ul.appendChild(li);
    });
}

async function addEntry() {
    const site = document.getElementById("site").value;
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    if (!site || !username || !password)
        return alert("Fill all fields!");

    passwordBook.push({ site, username, password });
    await saveEncrypted();
    displayEntries();

    document.getElementById("site").value = "";
    document.getElementById("username").value = "";
    document.getElementById("password").value = "";
}

function exportJSON() {
    const blob = new Blob([JSON.stringify(passwordBook, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "password_book.json";
    a.click();
}

function exportTXT() {
    let text = "";
    passwordBook.forEach(e => {
        text += `${e.site} | ${e.username} | ${e.password}\n`;
    });

    const blob = new Blob([text], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "password_book.txt";
    a.click();
}
